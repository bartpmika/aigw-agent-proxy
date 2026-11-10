# aigw-agent-proxy

**Prototype.** A small local forward proxy, written in Rust, that puts AI coding agents
(Claude Code, Codex, anything that honors `HTTPS_PROXY`) under
**Prisma AIRS AI Gateway** governance without changing the agent. It
registers as a **hybrid gateway** in your SCM tenant.

Every LLM call shows up in SCM logs tagged with **who and what made it**:
- the user (`_user`)
- the process (`_process`)
- the machine (`_hostname`)
- the user agent

The call is checked by your workspace guardrails and budgets, then sent on to
its original destination unchanged.

**The agent's other web traffic (curl, git, WebFetch) is checked by the same
guardrails.**

## Quick start (macOS)

1. **SCM.**
   - Create a **hybrid deployment** and a **workspace API key**.
   - Attach your guardrails at the workspace level.
   - Details: [Configure in SCM](#configure-in-scm).
2. **Install.** Download `aigw-agent-proxy-macos-universal.tar.gz` from the
   [latest release](https://github.com/bartpmika/aigw-agent-proxy/releases/latest),
   then:
   ```sh
   cd ~/Downloads
   tar -xzf aigw-agent-proxy-macos-universal.tar.gz && cd aigw-agent-proxy
   xattr -d com.apple.quarantine aigw-agent-proxy        # unsigned binary
   sudo mkdir -p /usr/local/bin
   sudo cp aigw-agent-proxy claude-proxy /usr/local/bin/
   sudo ln -sf /usr/local/bin/claude-proxy /usr/local/bin/codex-proxy
   ```
3. **Configure.** Put the values from step 1 into the env file:
   ```sh
   mkdir -p ~/.aigw-agent-proxy && chmod 700 ~/.aigw-agent-proxy
   cp proxy.env.example ~/.aigw-agent-proxy/proxy.env
   chmod 600 ~/.aigw-agent-proxy/proxy.env
   open -e ~/.aigw-agent-proxy/proxy.env
   ```
4. **Run.**
   ```sh
   claude-proxy        # Claude Code through the proxy (starts the proxy if needed)
   codex-proxy         # or Codex
   ```
5. **Check.**
   - In SCM, *AI Gateway → Logs* shows the session with `_user`, `_process`
     and `_hostname`.
   - In the session, run
     `! curl -sS "https://www.google.com/search?q=my+social+security+number+is+538-21-4076"`.
     It returns `403 guardrail_blocked` when an AIRS DLP guardrail with deny
     is attached.

## What it does

- **LLM governance.** Calls to `api.anthropic.com` and `api.openai.com`, and
  Codex signed in with ChatGPT (`chatgpt.com/backend-api/codex`), are
  decrypted with a local CA and run through:
  - workspace and org guardrails, including AIRS: input, and streamed output
    (buffered, then scanned)
  - API key and workspace budgets and rate limits
  - SCM logging and cost analytics
- **Caller identity.** Every log carries who made the call, read from the
  OS, not from the request. Clients can't spoof these fields.

  | Field | Meaning |
  | --- | --- |
  | `_user` | OS user (optionally mapped to `user@domain`) |
  | `_process` | Calling executable, e.g. `claude`, `codex`, `curl` |
  | `_hostname` | Machine name (`_domain` holds its DNS domain) |
  | `_user_agent` | The agent's User-Agent, e.g. `claude-cli/2.x (external, cli)` |
  | `_agent` | Detected agent family, e.g. `claude-code` |

  Also logged: `_pid`, `_process_path`, `_process_version`,
  `_process_args` (secrets redacted), `_cwd`, `_parent_chain`, and the code
  signature (`_signature_id`, `_signature_team`).
- **Web inspection.** Other HTTP(S) traffic from the agent is checked in
  both directions.
  - **Requests** (URL plus body) go through the workspace **request (input)
    guardrails**.
  - **Responses** go through the **response (output) guardrails** before the
    agent sees them, for example a fetched page with an SSN or injected
    instructions.
  - **What's scanned in a response:** for HTML, the text a model would read
    (visible and hidden text, plus comments). Tags and links aren't scanned,
    so a page linking to a flagged site isn't blocked for that.
  - **Size and scope:** the first 256 KB of each text response
    (`webInspection.maxScanBytes`). Binary downloads, event streams and
    package registries aren't scanned.
  - **On a block:** a 403, logged in SCM as provider `web`.
  - **Turning response scanning off:** `FORWARD_PROXY_WEB_RESPONSES=0`.
- **Budgets across laptops.** API-key and workspace usage limits set in SCM
  (cost or tokens) hold across every machine using the key, with no Redis.
  - **Reporting:** each proxy reports the spend it hasn't reported yet to the
    control plane every 20 s (`USAGE_RESYNC_INTERVAL_MS`).
  - **Enforcement:** the control plane totals all machines and marks the key
    or workspace exhausted. Every proxy re-checks at least every 60 s
    (`KEY_DETAILS_TTL_MS`), sooner when the control plane signals a budget
    change, and then blocks with a usage-limit error.
  - **API-key limits:** they need the organisation setting that enables
    API-key limits.
- **MCP inspection.** Calls to remote MCP servers (HTTP / streamable HTTP)
  that go through the proxy are understood, not just forwarded.
  - **Requests:** `tools/call`, `resources/read` and `prompts/get` arguments
    are checked with the workspace **MCP input guardrails** (or the input
    guardrails when none are set).
  - **Results:** checked with the **MCP output guardrails** (or the output
    guardrails).
  - **On a block:** the agent gets an MCP error (`Blocked by AI Gateway
    guardrail: …`).
  - **Logging:** every call is logged in SCM as provider `mcp`, with
    `_mcp_server`, `_mcp_tool` and the caller identity.
  - **Everything else** (initialize, listing, notifications) is forwarded to
    the server unchanged.
- **Routing (optional).** Local routes or SCM configs can do fallback,
  loadbalance, conditional routing, retries, circuit breaker and cache. They
  can also send Anthropic traffic to OpenAI, or the reverse; formats are
  translated in both directions.

Without any routes, traffic goes to where the agent sent it, with the
agent's own credentials. The proxy adds governance only.

## Install

**Download (macOS, Apple Silicon and Intel).** Get
`aigw-agent-proxy-macos-universal.tar.gz` from the
[latest release](https://github.com/bartpmika/aigw-agent-proxy/releases/latest).
This is the full build.

```sh
tar -xzf aigw-agent-proxy-macos-universal.tar.gz && cd aigw-agent-proxy
xattr -d com.apple.quarantine aigw-agent-proxy   # unsigned binary
sudo mkdir -p /usr/local/bin
sudo cp aigw-agent-proxy claude-proxy /usr/local/bin/
sudo ln -sf /usr/local/bin/claude-proxy /usr/local/bin/codex-proxy   # for Codex
```

**Or build from source.** This needs Rust; Claude Code (`claude`) is needed
either way.

```sh
# Rust toolchain, if needed: https://rustup.rs
git clone https://github.com/bartpmika/aigw-agent-proxy && cd aigw-agent-proxy
cargo build --release                       # ~4 MB binary
sudo mkdir -p /usr/local/bin
sudo cp target/release/aigw-agent-proxy scripts/claude-proxy /usr/local/bin/
sudo ln -sf /usr/local/bin/claude-proxy /usr/local/bin/codex-proxy
```

Optional full build: `cargo build --release --features gateway`. It adds the
gateway's API mode on `PORT`, and routing to Bedrock, Vertex, Gemini, Azure,
groq, mistral and about 70 other providers. The agent proxy doesn't need it.

## Configure in SCM

1. **Hybrid deployment.** Go to *AI Gateway → Deployments* and create a
   **hybrid** deployment. Its setup details give you `PORTKEY_CLIENT_AUTH`,
   `ORGANISATIONS_TO_SYNC` and the control-plane URLs. The proxy is the
   gateway, so no container is needed. It shows as connected once it's
   running.
2. **API key.** Go to *AI Gateway → API Keys* and create a workspace API key.
   - The proxy uses it to authenticate to the control plane. Its workspace
     decides which guardrails, budgets and logs apply.
   - **One key can serve many proxy installs**, for example every laptop on a
     team. Each install still reports its own `_user`, `_process` and
     `_hostname`, so calls stay attributable.
   - The deployment values from step 1 (`PORTKEY_CLIENT_AUTH`,
     `ORGANISATIONS_TO_SYNC`) can be shared the same way.
3. **Guardrails (optional).** Attach guardrails at the **workspace** level
   (workspace defaults → input/output guardrails), with **deny** enabled to
   block. For AIRS URL filtering, make sure the guardrail references the AIRS
   profile **by name**. A stale `profile_id` makes AIRS skip categories added
   to the profile later.

## Configure the proxy

```sh
mkdir -p ~/.aigw-agent-proxy && chmod 700 ~/.aigw-agent-proxy
cp proxy.env.example ~/.aigw-agent-proxy/proxy.env && chmod 600 ~/.aigw-agent-proxy/proxy.env
$EDITOR ~/.aigw-agent-proxy/proxy.env       # values from steps 1 and 2
```

Optional: point `FORWARD_PROXY_CONFIG` at a JSON file for routes, static
metadata, identity mapping or web-inspection bypasses
(see `forward-proxy.example.json`).

## Run

**With the launcher (recommended).** `claude-proxy` (or `codex-proxy`)
starts the proxy in the background when needed, logging to
`~/.aigw-agent-proxy/proxy.log`, and then runs the agent through it.

**Manually**, for example to watch the proxy's output or use another agent:

```sh
# Terminal 1: the proxy (Ctrl-C stops it)
set -a; source ~/.aigw-agent-proxy/proxy.env; set +a
export FORWARD_PROXY_CA_DIR="${FORWARD_PROXY_CA_DIR:-$HOME/.aigw-agent-proxy}"
aigw-agent-proxy

# Terminal 2: any agent
export HTTPS_PROXY=http://127.0.0.1:8789 HTTP_PROXY=http://127.0.0.1:8789
export NO_PROXY=localhost,127.0.0.1
export NODE_EXTRA_CA_CERTS=~/.aigw-agent-proxy/ca.cert.pem        # Node agents (Claude Code)
export SSL_CERT_FILE=~/.aigw-agent-proxy/ca-bundle.pem            # curl, git, Python
claude
```

To check that the proxy is up, run
`curl -s --noproxy '*' http://127.0.0.1:8789/ca.pem | head -1`. It prints the
CA certificate's first line.

## Use with Claude Code

```sh
claude-proxy            # same arguments as `claude`
```

`claude-proxy` does four things:

- starts the proxy if it isn't running, and restarts it when the binary on
  disk is newer or another program holds the port, so it always runs the
  current build;
- sets `HTTPS_PROXY`/`HTTP_PROXY`, keeping localhost direct;
- makes Claude Code and the tools it runs (curl, git, Python, AWS CLI) trust
  the proxy's CA;
- launches `claude`.

Optional: `~/.aigw-agent-proxy/claude.settings.json` is passed to Claude Code
as `--settings`, for example to add a status line for proxied sessions.

The local CA is created on first run, in `~/.aigw-agent-proxy/`. Nothing is
installed in the system keychain.

To check it's working:

- In SCM, *AI Gateway → Logs* shows the session's requests with
  `_source: forward-proxy`, the user and the process.
- `! curl -sS "https://www.google.com/search?q=my+social+security+number+is+538-21-4076"`
  from inside the session returns `403 guardrail_blocked` when an AIRS DLP
  guardrail with deny is attached.

## Use with Codex

```sh
codex-proxy             # same arguments as `codex`
```

This works with both sign-in modes:

- **API key:** Codex calls `api.openai.com`.
- **ChatGPT sign-in:** Codex calls the ChatGPT backend, which uses the same
  Responses format. Requests and the ChatGPT token pass through unchanged.

Usage is billed to the ChatGPT subscription, so the cost SCM shows for these
calls is the API-list-price equivalent.

Newer Codex versions can stream over WebSockets. That mode passes through
without inspection; the default HTTP streaming is governed.

## Other agents

Set `HTTPS_PROXY=http://127.0.0.1:8789` plus the CA variables from
`scripts/claude-proxy`.

- **Fully governed:** agents that call Anthropic or OpenAI directly with an
  API key (Cline, Roo Code, Aider, opencode).
- **Web inspection only:** agents with their own backends (Gemini CLI,
  Copilot, Cursor) are covered by web inspection but aren't logged as LLM
  calls.

## Limits

- **Tested only on Apple Silicon (macOS) with Claude Code.** Codex, other
  agents, Intel Macs and other operating systems are untested. MCP
  inspection was tested with direct MCP requests to a public server and a
  mock, not through an agent's MCP client.
- **Budgets:** enforcement is eventually consistent. A machine can overshoot
  a limit by roughly the spend made before the next report and refresh,
  about a minute at the defaults. Request rate limits are enforced per
  machine, not across machines. Usage-limit policies (per-user or metadata
  budgets) and virtual-key budgets aren't implemented yet.
- **MCP:** only remote MCP servers reached through the proxy are covered.
  Local stdio servers (most installed MCP servers) and servers on localhost
  don't send traffic through the proxy.
- Only traffic that honors proxy variables is covered. Raw sockets, ssh and
  DNS go direct, and localhost isn't inspected.
- Clients that pin certificates, or ignore the CA variables, fail closed. Add
  their hosts to `webInspection.bypassHosts`.
- Guardrail checks run in the proxy: regex, contains and Prisma AIRS. Other
  guardrail plugin types pass, and the log records an error.
- Caller identity relies on macOS tools (`lsof`, `ps`, `codesign`).

## License

Copyright (c) 2026 Palo Alto Networks, Inc. All rights reserved. No license
is granted for this project's own code. It's published for viewing only;
copying, modifying or redistributing it requires permission.

The repository contains material derived from the
[Portkey AI Gateway](https://github.com/Portkey-AI/gateway), which remains
under the MIT License (Copyright (c) 2024 Portkey, Inc).

Part of that material comes from the gateway's 2.0.0 pre-release branch.
That branch has no LICENSE file; its package.json declares MIT.

[NOTICE](NOTICE) has:
- the list of derived files, including those from the 2.0.0 branch;
- the full license notices for Portkey and mustache.js.

[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt) lists the licenses of
the Rust crates in the binary.
