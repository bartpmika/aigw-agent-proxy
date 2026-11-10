//! Who is calling: the local process behind a proxy connection (lsof, ps,
//! codesign) and the machine it runs on.

use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use tokio::process::Command;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_PARENT_DEPTH: usize = 6;
const MAX_ARGS_LENGTH: usize = 300;

#[derive(Debug, Clone, Default)]
pub struct CodeSignature {
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    /// "valid", "invalid" or "unsigned".
    pub status: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct LocalClient {
    pub pid: u32,
    pub os_user: Option<String>,
    pub executable: Option<String>,
    pub executable_path: Option<String>,
    pub version: Option<String>,
    pub args: Option<String>,
    pub cwd: Option<String>,
    pub parent_chain: Option<String>,
    pub signature: Option<CodeSignature>,
}

async fn run(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::time::timeout(LOOKUP_TIMEOUT, Command::new(program).args(args).output())
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parses `lsof -F pL` into (pid, login) pairs.
fn parse_lsof(output: &str) -> Vec<(u32, Option<String>)> {
    let mut out: Vec<(u32, Option<String>)> = Vec::new();
    for line in output.lines() {
        if let Some(pid) = line.strip_prefix('p') {
            if let Ok(pid) = pid.parse() {
                out.push((pid, None));
            }
        } else if let Some(login) = line.strip_prefix('L') {
            if let Some(last) = out.last_mut() {
                last.1 = Some(login.to_string());
            }
        }
    }
    out
}

/// Parses `lsof -a -p <pid> -d cwd,txt -Ffn` into (cwd, executable path).
pub fn parse_process_files(output: &str) -> (Option<String>, Option<String>) {
    static SHARED_LIB: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.(dylib|so)(\.|$)|/dyld|/usr/lib/").unwrap());
    let (mut fd, mut cwd, mut exe) = (String::new(), None, None);
    for line in output.lines() {
        if let Some(f) = line.strip_prefix('f') {
            fd = f.to_string();
        } else if let Some(name) = line.strip_prefix('n') {
            if fd == "cwd" && cwd.is_none() {
                cwd = Some(name.to_string());
            } else if fd == "txt" && exe.is_none() && !SHARED_LIB.is_match(name) {
                exe = Some(name.to_string());
            }
        }
    }
    (cwd, exe)
}

/// Walks `ps -ax -o pid=,ppid=,comm=` from `pid` up to launchd/init.
pub fn build_parent_chain(ps: &str, pid: u32) -> Option<String> {
    let mut table: HashMap<u32, (u32, String)> = HashMap::new();
    for line in ps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(p), Some(pp)) = (parts.next(), parts.next()) else { continue };
        let name: String = parts.collect::<Vec<_>>().join(" ");
        if let (Ok(p), Ok(pp)) = (p.parse::<u32>(), pp.parse::<u32>()) {
            let base = Path::new(name.trim())
                .file_name()
                .map(|f| f.to_string_lossy().trim_start_matches('-').to_string())
                .unwrap_or_default();
            table.insert(p, (pp, base));
        }
    }
    let mut chain = Vec::new();
    let mut current = table.get(&pid).map(|(pp, _)| *pp);
    while let Some(c) = current {
        if c <= 1 || chain.len() >= MAX_PARENT_DEPTH {
            break;
        }
        let Some((pp, name)) = table.get(&c) else { break };
        chain.push(name.clone());
        current = Some(*pp);
    }
    (!chain.is_empty()).then(|| chain.join(" < "))
}

pub fn version_from_path(path: Option<&str>) -> Option<String> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?:^|[/@-])v?(\d+\.\d+\.\d+)(?:/|$)").unwrap());
    RE.captures(path?).map(|c| c[1].to_string())
}

/// Redacts values that look like credentials before logging a command line.
pub fn redact_args(args: &str) -> String {
    static FLAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(--?[\w-]*(?:key|token|secret|password|passwd|auth|credential)[\w-]*)([=\s]+)(\S+)").unwrap()
    });
    static URL_CREDS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(\w+://)[^/\s:@]+:[^/\s@]+@").unwrap());
    static TOKEN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(sk-[\w-]{8,}|[A-Za-z0-9_\-]{32,})\b").unwrap());
    let r = FLAG.replace_all(args, "${1}${2}[redacted]");
    let r = URL_CREDS.replace_all(&r, "${1}[redacted]@");
    let r = TOKEN.replace_all(&r, "[redacted]").into_owned();
    if r.chars().count() > MAX_ARGS_LENGTH {
        format!("{}...", r.chars().take(MAX_ARGS_LENGTH).collect::<String>())
    } else {
        r
    }
}

static SIGNATURES: LazyLock<Mutex<HashMap<String, CodeSignature>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// macOS code signature, cached per executable path + mtime.
async fn code_signature(path: &str) -> Option<CodeSignature> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    let key = format!("{path}:{mtime:?}");
    if let Some(s) = SIGNATURES.lock().unwrap().get(&key) {
        return Some(s.clone());
    }
    // codesign prints details on stderr and exits non-zero when unsigned.
    let details = tokio::time::timeout(
        LOOKUP_TIMEOUT,
        Command::new("codesign").args(["-dv", path]).output(),
    )
    .await
    .ok()?
    .ok()?;
    let signature = if !details.status.success() {
        CodeSignature { status: "unsigned", ..Default::default() }
    } else {
        let text = String::from_utf8_lossy(&details.stderr);
        let field = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}=")))
                .map(str::to_string)
                .filter(|v| v != "not set")
        };
        let valid = tokio::time::timeout(
            LOOKUP_TIMEOUT * 10,
            Command::new("codesign").args(["--verify", path]).status(),
        )
        .await
        .ok()
        .and_then(|r| r.ok())
        .map(|s| s.success())
        .unwrap_or(false);
        CodeSignature {
            identifier: field("Identifier"),
            team_id: field("TeamIdentifier"),
            status: if valid { "valid" } else { "invalid" },
        }
    };
    SIGNATURES.lock().unwrap().insert(key, signature.clone());
    Some(signature)
}

/// Finds the local process behind a loopback connection and describes it.
pub async fn lookup_local_client(remote: IpAddr, remote_port: u16) -> Option<LocalClient> {
    let ip = match remote {
        IpAddr::V4(v4) if v4.is_loopback() => v4.to_string(),
        IpAddr::V6(v6) if v6.is_loopback() => "[::1]".to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) if v4.is_loopback() => v4.to_string(),
            _ => return None,
        },
        _ => return None,
    };
    let spec = format!("-iTCP@{ip}:{remote_port}");
    let lsof = run("lsof", &["-nP", &spec, "-sTCP:ESTABLISHED", "-FpL"]).await?;
    let me = std::process::id();
    let (pid, login) = parse_lsof(&lsof).into_iter().find(|(p, _)| *p != me)?;
    let pid_s = pid.to_string();
    let files_args = ["-a", "-p", pid_s.as_str(), "-d", "cwd,txt", "-Ffn"];
    let args_args = ["-o", "args=", "-p", pid_s.as_str()];
    let (files, ps, args) = tokio::join!(
        run("lsof", &files_args),
        run("ps", &["-ax", "-o", "pid=,ppid=,comm="]),
        run("ps", &args_args),
    );
    let (cwd, executable_path) = parse_process_files(files.as_deref().unwrap_or(""));
    let ps = ps.unwrap_or_default();
    let comm = ps.lines().find_map(|l| {
        let mut p = l.split_whitespace();
        (p.next() == Some(pid_s.as_str())).then(|| p.skip(1).collect::<Vec<_>>().join(" "))
    });
    let executable = executable_path
        .as_deref()
        .or(comm.as_deref())
        .and_then(|p| Path::new(p).file_name())
        .map(|f| f.to_string_lossy().into_owned());
    let signature = match &executable_path {
        Some(p) => code_signature(p).await,
        None => None,
    };
    Some(LocalClient {
        pid,
        os_user: login,
        executable,
        version: version_from_path(executable_path.as_deref()),
        executable_path,
        args: args.map(|a| a.trim().to_string()).filter(|a| !a.is_empty()).map(|a| redact_args(&a)),
        cwd,
        parent_chain: build_parent_chain(&ps, pid),
        signature,
    })
}

/// Names the agent: executable first (from the OS), then the user agent.
pub fn detect_agent(executable: Option<&str>, user_agent: Option<&str>) -> String {
    static BY_EXE: LazyLock<Vec<(Regex, &str)>> = LazyLock::new(|| {
        [("(?i)^claude$", "claude-code"), ("(?i)^codex", "codex"), ("(?i)^cursor", "cursor"),
         ("(?i)^windsurf", "windsurf"), ("(?i)^gemini$", "gemini-cli"), ("(?i)^aider$", "aider")]
            .iter().map(|(r, a)| (Regex::new(r).unwrap(), *a)).collect()
    });
    static BY_UA: LazyLock<Vec<(Regex, &str)>> = LazyLock::new(|| {
        [("(?i)^claude-(cli|code)/", "claude-code"), ("(?i)^codex", "codex"),
         ("(?i)cursor", "cursor"), ("(?i)aider", "aider")]
            .iter().map(|(r, a)| (Regex::new(r).unwrap(), *a)).collect()
    });
    let exe = executable.unwrap_or("");
    if let Some((_, a)) = BY_EXE.iter().find(|(r, _)| r.is_match(exe)) {
        return a.to_string();
    }
    if let Some((_, a)) = BY_UA.iter().find(|(r, _)| r.is_match(user_agent.unwrap_or(""))) {
        return a.to_string();
    }
    if exe.is_empty() { "unknown".into() } else { exe.to_string() }
}

#[derive(Debug, Clone)]
pub struct HostIdentity {
    pub hostname: String,
    pub domain: Option<String>,
}

pub fn domain_from_fqdn(fqdn: &str) -> Option<String> {
    let (_, domain) = fqdn.split_once('.')?;
    let domain = domain.to_lowercase();
    (!domain.is_empty() && domain != "local").then_some(domain)
}

pub fn parse_ad_domain(output: &str) -> Option<String> {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?im)^\s*Active Directory Domain\s*=\s*(\S+)").unwrap());
    RE.captures(output).map(|c| c[1].to_lowercase())
}

pub fn parse_search_domain(output: &str) -> Option<String> {
    static SCUTIL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)search domain\[\d+\]\s*:\s*(\S+)").unwrap());
    static RESOLV: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?im)^\s*(?:search|domain)\s+([a-z0-9][\w.-]*)\s*$").unwrap());
    let d = SCUTIL
        .captures(output)
        .or_else(|| RESOLV.captures(output))
        .map(|c| c[1].to_lowercase())?;
    (d != "local").then_some(d)
}

static HOST: LazyLock<Mutex<Option<(Instant, HostIdentity)>>> = LazyLock::new(|| Mutex::new(None));

/// Hostname and domain, refreshed every 5 minutes (networks/VPN change).
pub async fn host_identity() -> HostIdentity {
    if let Some((at, h)) = HOST.lock().unwrap().as_ref() {
        if at.elapsed() < Duration::from_secs(300) {
            return h.clone();
        }
    }
    let fqdn = run("hostname", &[]).await.map(|s| s.trim().to_string()).unwrap_or_default();
    let hostname = fqdn.split('.').next().unwrap_or("").to_string();
    let mut domain = None;
    if cfg!(target_os = "macos") {
        domain = run("dsconfigad", &["-show"]).await.as_deref().and_then(parse_ad_domain);
    }
    domain = domain.or_else(|| domain_from_fqdn(&fqdn));
    if domain.is_none() {
        domain = if cfg!(target_os = "macos") {
            run("scutil", &["--dns"]).await.as_deref().and_then(parse_search_domain)
        } else {
            std::fs::read_to_string("/etc/resolv.conf").ok().as_deref().and_then(parse_search_domain)
        };
    }
    let identity = HostIdentity { hostname, domain };
    *HOST.lock().unwrap() = Some((Instant::now(), identity.clone()));
    identity
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_process_files_and_parents() {
        let files = "p1\nfcwd\nn/Users/b/proj\nftxt\nn/opt/homebrew/Caskroom/claude-code/2.1.287/claude\nftxt\nn/usr/lib/dyld\n";
        assert_eq!(
            parse_process_files(files),
            (Some("/Users/b/proj".into()), Some("/opt/homebrew/Caskroom/claude-code/2.1.287/claude".into()))
        );
        let ps = "    1     0 /sbin/launchd\n  643     1 /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal\n  742   643 login\n  747   742 -zsh\n 1358   747 claude\n";
        assert_eq!(build_parent_chain(ps, 1358).as_deref(), Some("zsh < login < Terminal"));
        assert_eq!(build_parent_chain(ps, 643), None);
    }

    #[test]
    fn versions_and_redaction() {
        assert_eq!(version_from_path(Some("/opt/homebrew/Caskroom/claude-code/2.1.287/claude")).as_deref(), Some("2.1.287"));
        assert_eq!(version_from_path(Some("/usr/local/bin/node")), None);
        assert_eq!(redact_args("claude -c --model opus"), "claude -c --model opus");
        assert_eq!(redact_args("tool --api-key sk-ant-abc123456789 run"), "tool --api-key [redacted] run");
        assert_eq!(redact_args("git clone https://me:hunter2@github.com/x"), "git clone https://[redacted]@github.com/x");
        assert!(redact_args(&"a ".repeat(400)).ends_with("..."));
    }

    #[test]
    fn agents_and_domains() {
        assert_eq!(detect_agent(Some("claude"), Some("python-requests/2")), "claude-code");
        assert_eq!(detect_agent(Some("node"), Some("claude-cli/2.1.287 (external, cli)")), "claude-code");
        assert_eq!(detect_agent(None, None), "unknown");
        assert_eq!(domain_from_fqdn("laptop.corp.example.com").as_deref(), Some("corp.example.com"));
        assert_eq!(domain_from_fqdn("Alices-MacBook-Air.local"), None);
        assert_eq!(parse_ad_domain("Active Directory Domain = EMEA.Corp.com\n").as_deref(), Some("emea.corp.com"));
        assert_eq!(parse_search_domain("resolver #2\n  domain   : local\n"), None);
        assert_eq!(parse_search_domain("nameserver 1.1.1.1\nsearch corp.example.com\n").as_deref(), Some("corp.example.com"));
    }
}
