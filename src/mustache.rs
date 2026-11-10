//! Port of `@portkey-ai/mustache` (the mustache.js 4.2 fork the TS gateway
//! renders prompts with), quirks included: escaping is JSON-string escaping,
//! arrays/objects render as JSON, `{{>> var}}` variable partials, and
//! malformed tags fall back to text. Parser and writer mirror the JS code.

use regex::Regex;
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
struct Token {
    kind: String,
    value: String,
    end: usize,
    indentation: String,
    tag_index: usize,
    line_has_non_space: bool,
    children: Vec<Token>,
}

impl Token {
    fn new(kind: &str, value: String, end: usize) -> Self {
        Self { kind: kind.into(), value, end, indentation: String::new(), tag_index: 0, line_has_non_space: false, children: Vec::new() }
    }
}

struct Scanner {
    string: String,
    tail: String,
    pos: usize,
}

impl Scanner {
    fn eos(&self) -> bool {
        self.tail.is_empty()
    }
    fn scan(&mut self, re: &Regex) -> String {
        match re.find(&self.tail) {
            Some(m) if m.start() == 0 => {
                let s = m.as_str().to_string();
                self.tail = self.tail[s.len()..].to_string();
                self.pos += s.len();
                s
            }
            _ => String::new(),
        }
    }
    /// JS `getMatchedIndex(re).tailIndex`.
    fn tail_index(&self, re: &Regex) -> i64 {
        re.find(&self.tail).map(|m| m.start() as i64).unwrap_or(-1)
    }
    fn scan_until(&mut self, re: &Regex) -> String {
        let m = match re.find(&self.tail).map(|m| m.start()) {
            None => std::mem::take(&mut self.tail),
            Some(0) => String::new(),
            Some(i) => {
                let m = self.tail[..i].to_string();
                self.tail = self.tail[i..].to_string();
                m
            }
        };
        self.pos += m.len();
        m
    }
}

struct Tags {
    open: String,
    opening: Regex,
    closing: Regex,
    closing_curly: Regex,
}

fn compile_tags(open: &str, close: &str) -> Tags {
    Tags {
        open: open.to_string(),
        opening: Regex::new(&format!(r"{}\s*", regex::escape(open))).unwrap(),
        closing: Regex::new(&format!(r"\s*{}", regex::escape(close))).unwrap(),
        closing_curly: Regex::new(&format!(r"\s*{}", regex::escape(&format!("}}{close}")))).unwrap(),
    }
}

const MAX_SPECIAL_NAME: i64 = 50;

fn parse(template: &str) -> Vec<Token> {
    if template.is_empty() {
        return Vec::new();
    }
    let tag_re = Regex::new(r"#|\^|/|>>|>|\{|&|=|!").unwrap();
    let white_re = Regex::new(r"^\s*").unwrap();
    let equals_re = Regex::new(r"\s*=").unwrap();
    let curly_re = Regex::new(r"\s*\}").unwrap();
    let mut tags = compile_tags("{{", "}}");
    let mut sc = Scanner { string: template.to_string(), tail: template.to_string(), pos: 0 };
    let mut tokens: Vec<Option<Token>> = Vec::new();
    let mut spaces: Vec<usize> = Vec::new();
    let (mut has_tag, mut non_space, mut line_has_non_space) = (false, false, false);
    let mut indentation = String::new();
    let mut tag_index = 0usize;

    macro_rules! strip_space {
        () => {
            if has_tag && !non_space {
                while let Some(i) = spaces.pop() {
                    if i < tokens.len() {
                        tokens[i] = None;
                    }
                }
            } else {
                spaces.clear();
            }
            has_tag = false;
            non_space = false;
        };
    }
    // JS updateExistingScannedCopyWithText: re-emit `text` and rewind.
    let rewind_with_text = |tokens: &mut Vec<Option<Token>>, sc: &mut Scanner, text: &str| {
        let last = tokens.iter().rev().flatten().next().map(|t| t.end).unwrap_or(0);
        let mut offset = 0;
        for ch in text.chars() {
            offset += ch.len_utf8();
            tokens.push(Some(Token::new("text", ch.to_string(), last + offset)));
        }
        sc.pos = last + text.len();
        sc.tail = sc.string.get(sc.pos..).unwrap_or("").to_string();
    };

    while !sc.eos() {
        let mut start = sc.pos;
        let value = sc.scan_until(&tags.opening);
        for ch in value.chars() {
            if ch.is_whitespace() {
                spaces.push(tokens.len());
                indentation.push(ch);
            } else {
                non_space = true;
                line_has_non_space = true;
                indentation.push(' ');
            }
            start += ch.len_utf8();
            tokens.push(Some(Token::new("text", ch.to_string(), start)));
            if ch == '\n' {
                strip_space!();
                indentation.clear();
                tag_index = 0;
                line_has_non_space = false;
            }
        }
        if sc.scan(&tags.opening).is_empty() {
            break;
        }
        has_tag = true;
        let mut kind = {
            let t = sc.scan(&tag_re);
            if t.is_empty() { "name".to_string() } else { t }
        };
        sc.scan(&white_re);
        let value;
        if kind == "=" {
            if sc.tail_index(&tags.closing) == -1 {
                let t = format!("{}=", tags.open);
                rewind_with_text(&mut tokens, &mut sc, &t);
                continue;
            }
            value = sc.scan_until(&equals_re);
            sc.scan(&equals_re);
            sc.scan(&tags.closing);
        } else if kind == "{" {
            if sc.tail_index(&tags.closing) == -1 {
                let t = format!("{}{{", tags.open);
                rewind_with_text(&mut tokens, &mut sc, &t);
                continue;
            }
            value = sc.scan_until(&tags.closing_curly);
            sc.scan(&curly_re);
            sc.scan(&tags.closing);
            kind = "&".into();
        } else if kind == ">" || kind == ">>" {
            let (o, c) = (sc.tail_index(&tags.opening), sc.tail_index(&tags.closing));
            if (c > -1 && o > -1 && o < c) || c > MAX_SPECIAL_NAME {
                continue;
            }
            value = sc.scan_until(&tags.closing);
        } else {
            value = sc.scan_until(&tags.closing);
        }
        if ["#", "^", "/", ">", ">>"].contains(&kind.as_str()) {
            let (o, c) = (sc.tail_index(&tags.opening), sc.tail_index(&tags.closing));
            let issue = c == -1 || (o > -1 && o < c);
            let pk_issue = issue || c > MAX_SPECIAL_NAME;
            if ((kind == ">" || kind == ">>") && pk_issue) || issue {
                let t = format!("{}{}", tags.open, kind);
                rewind_with_text(&mut tokens, &mut sc, &t);
                continue;
            } else if sc.scan(&tags.closing).is_empty() {
                continue;
            }
        }
        if kind == "name" {
            let (o, c) = (sc.tail_index(&tags.opening), sc.tail_index(&tags.closing));
            if o > -1 && o < c {
                let t = tags.open.clone();
                rewind_with_text(&mut tokens, &mut sc, &t);
                continue;
            }
            if c == -1 {
                let t = tags.open.clone();
                rewind_with_text(&mut tokens, &mut sc, &t);
                continue;
            }
            sc.scan(&tags.closing);
        }
        let mut token = Token::new(&kind, value.clone(), sc.pos);
        if kind == ">" || kind == ">>" {
            token.indentation = indentation.clone();
            token.tag_index = tag_index;
            token.line_has_non_space = line_has_non_space;
        }
        tag_index += 1;
        tokens.push(Some(token));
        if kind == "name" || kind == "{" || kind == "&" {
            non_space = true;
        } else if kind == "=" {
            let mut parts = value.split_whitespace();
            if let (Some(o), Some(c)) = (parts.next(), parts.next()) {
                tags = compile_tags(o, c);
            }
        }
    }
    // As in JS: filter first, then strip using the pre-filter indices.
    let mut tokens: Vec<Option<Token>> = tokens.into_iter().flatten().map(Some).collect();
    if has_tag && !non_space {
        while let Some(i) = spaces.pop() {
            if i < tokens.len() {
                tokens[i] = None;
            }
        }
    }
    nest(squash(tokens.into_iter().flatten().collect()))
}

fn squash(tokens: Vec<Token>) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::new();
    for t in tokens {
        match out.last_mut() {
            Some(last) if t.kind == "text" && last.kind == "text" => {
                last.value.push_str(&t.value);
                last.end = t.end;
            }
            _ => out.push(t),
        }
    }
    out
}

fn nest(tokens: Vec<Token>) -> Vec<Token> {
    // Stack of open sections; the bottom collects the root.
    let mut stack: Vec<Token> = vec![Token::new("root", String::new(), 0)];
    for t in tokens {
        match t.kind.as_str() {
            "#" | "^" => stack.push(t),
            "/" => {
                if stack.len() > 1 {
                    let section = stack.pop().unwrap();
                    stack.last_mut().unwrap().children.push(section);
                }
            }
            _ => stack.last_mut().unwrap().children.push(t),
        }
    }
    // Unclosed sections stay attached where they were opened (JS keeps them
    // in their parent's collector).
    while stack.len() > 1 {
        let section = stack.pop().unwrap();
        stack.last_mut().unwrap().children.push(section);
    }
    stack.pop().unwrap().children
}

// ---------------------------------------------------------------- render

fn falsy(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64().is_none_or(|f| f == 0.0 || f.is_nan()),
        Value::String(s) => s.is_empty(),
        _ => false,
    }
}

/// JS String(number).
fn js_number(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        return i.to_string();
    }
    let f = n.as_f64().unwrap_or(0.0);
    if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{}", f as i64)
    } else {
        f.to_string()
    }
}

fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => js_number(n),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

/// JSON.stringify for values mustache.js renders as JSON.
fn js_json(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

fn property<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    match v {
        Value::Object(m) => m.get(name),
        Value::Array(a) => name.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    }
}

fn has_property(v: &Value, name: &str) -> bool {
    match v {
        Value::Object(m) => m.contains_key(name),
        Value::Array(a) => name == "length" || name.parse::<usize>().is_ok_and(|i| i < a.len()),
        _ => false,
    }
}

fn lookup(stack: &[&Value], name: &str) -> Value {
    if name == "." {
        return stack.last().map(|v| (*v).clone()).unwrap_or(Value::Null);
    }
    for view in stack.iter().rev() {
        if name.find('.').is_some_and(|i| i > 0) {
            let names: Vec<&str> = name.split('.').collect();
            let mut cur: Option<&Value> = Some(view);
            let mut hit = false;
            for (i, n) in names.iter().enumerate() {
                let Some(c) = cur.filter(|c| !c.is_null()) else { break };
                if i == names.len() - 1 {
                    hit = has_property(c, n) || matches!((c, *n), (Value::String(_), "length"));
                }
                cur = property(c, n);
            }
            if hit {
                return cur.cloned().unwrap_or(Value::Null);
            }
        } else if has_property(view, name) {
            return property(view, name).cloned().unwrap_or(Value::Null);
        }
    }
    Value::Null
}

fn indent_partial(partial: &str, indentation: &str, line_has_non_space: bool) -> String {
    let filtered: String = indentation.chars().filter(|c| *c == ' ' || *c == '\t').collect();
    partial
        .split('\n')
        .enumerate()
        .map(|(i, line)| if !line.is_empty() && (i > 0 || !line_has_non_space) { format!("{filtered}{line}") } else { line.to_string() })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_tokens(tokens: &[Token], stack: &mut Vec<Value>, partials: &Map<String, Value>) -> String {
    let mut out = String::new();
    for t in tokens {
        let refs: Vec<&Value> = stack.iter().collect();
        match t.kind.as_str() {
            "#" => {
                let value = lookup(&refs, &t.value);
                if falsy(&value) {
                    continue;
                }
                match &value {
                    Value::Array(items) => {
                        for item in items {
                            stack.push(item.clone());
                            out.push_str(&render_tokens(&t.children, stack, partials));
                            stack.pop();
                        }
                    }
                    Value::Object(_) | Value::String(_) | Value::Number(_) => {
                        stack.push(value.clone());
                        out.push_str(&render_tokens(&t.children, stack, partials));
                        stack.pop();
                    }
                    _ => out.push_str(&render_tokens(&t.children, stack, partials)),
                }
            }
            "^" => {
                let value = lookup(&refs, &t.value);
                if falsy(&value) || value.as_array().is_some_and(|a| a.is_empty()) {
                    out.push_str(&render_tokens(&t.children, stack, partials));
                }
            }
            ">" => {
                if let Some(p) = partials.get(&t.value).filter(|p| !p.is_null()) {
                    let p = js_string(p);
                    let p = if t.tag_index == 0 && !t.indentation.is_empty() { indent_partial(&p, &t.indentation, t.line_has_non_space) } else { p };
                    out.push_str(&render_tokens(&parse(&p), stack, partials));
                }
            }
            ">>" => {
                if let Value::String(name) = lookup(&refs, &t.value) {
                    if let Some(p) = partials.get(&name).filter(|p| !falsy(p)) {
                        out.push_str(&render_tokens(&parse(&js_string(p)), stack, partials));
                    }
                }
            }
            "name" | "&" => {
                let value = lookup(&refs, &t.value);
                match &value {
                    Value::Array(items) => out.push_str(&items.iter().map(js_json).collect::<Vec<_>>().join(",")),
                    Value::Object(_) => out.push_str(&js_json(&value)),
                    Value::Null => {}
                    v if t.kind == "&" => out.push_str(&js_string(v)),
                    Value::Number(n) => out.push_str(&js_number(n)),
                    // mustache.escape: JSON.stringify(value).slice(1, -1).
                    v => {
                        let j = js_json(v);
                        let mut chars = j.chars();
                        chars.next();
                        chars.next_back();
                        out.push_str(chars.as_str());
                    }
                }
            }
            "text" => out.push_str(&t.value),
            _ => {}
        }
    }
    out
}

pub fn render(template: &str, view: &Value, partials: &Map<String, Value>) -> String {
    let mut stack = vec![view.clone()];
    render_tokens(&parse(template), &mut stack, partials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Expected outputs captured from @portkey-ai/mustache 2.1.3.
    #[test]
    fn matches_the_js_fork() {
        let none = Map::new();
        let r = |s: &str, v: Value| render(s, &v, &none);
        assert_eq!(r("a{{! c }}b", json!({})), "a }}b");
        assert_eq!(r("a{{& x}}b", json!({"x":"<q\""})), "a<q\"}}b");
        assert_eq!(r("a{{x}}b", json!({"x":"<q\""})), "a<q\\\"b");
        assert_eq!(r("{{x}}", json!({"x":true})), "ru");
        assert_eq!(r("{{x}}", json!({"x":[1,{"a":2}]})), "1,{\"a\":2}");
        assert_eq!(r("{{#l}}[{{.}}]{{/l}}", json!({"l":["a","b"]})), "[a][b]");
        assert_eq!(r("x\n  {{#s}}\n  y\n  {{/s}}\nz", json!({"s":true})), "x\n  y\nz");
        let mut p = Map::new();
        p.insert("p".into(), json!("hi {{n}}"));
        assert_eq!(render("{{> p}}!", &json!({"n":"N"}), &p), "hi N!");
        let mut p = Map::new();
        p.insert("p".into(), json!("P{{v}}"));
        assert_eq!(render("{{>> v}}", &json!({"v":"p"}), &p), "Pp");
        assert_eq!(r("a {{b", json!({})), "a {{b");
        assert_eq!(r("{{#x}}unclosed", json!({})), "");
        assert_eq!(r("{{a.b}}", json!({"a":{"b":"c"}})), "c");
        assert_eq!(r("{{{x}}}", json!({"x":"\""})), "\"");
    }
}
