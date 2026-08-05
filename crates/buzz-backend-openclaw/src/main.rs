//! One-shot OpenClaw enrollment provider bundled with Buzz Desktop.
//!
//! The provider only uses SSH for enrollment.  OpenClaw subsequently connects
//! directly to Buzz using the relay details in the v1 payload; this process is
//! never a runtime proxy.

use serde_json::{json, Value};
use std::io::Read;
use std::process::{Command, Stdio};

fn info() -> Value {
    json!({
        "ok": true,
        "name": "openclaw",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": 1,
        "description": "Enrolls agents with an OpenClaw host over SSH",
        "config_schema": {
            "type": "object",
            "properties": {
                "host": { "type": "string", "description": "SSH destination, e.g. openclaw@agent-host" },
                "rooms": { "type": "string", "description": "Comma-separated Buzz room UUIDs" },
                "port": { "type": "string", "description": "Optional SSH port" }
            },
            "required": ["host", "rooms"]
        },
        "enrollment": {
            "operation": "enroll",
            "one_time": true,
            "credential_fields": ["private_key_nsec", "auth_tag", "relay_url"]
        }
    })
}

fn error(message: impl Into<String>) -> Value {
    json!({"ok": false, "error": message.into()})
}

fn enroll(request: &Value) -> Value {
    let config = match request.get("provider_config").and_then(Value::as_object) {
        Some(config) => config,
        None => return error("provider_config must be an object"),
    };
    let host = match config.get("host").and_then(Value::as_str).filter(|v| !v.is_empty()) {
        Some(host) => host,
        None => return error("provider_config.host is required"),
    };
    if config.get("rooms").and_then(Value::as_str).is_none() {
        return error("provider_config.rooms is required");
    }
    let agent = match request.get("agent") {
        Some(agent) if agent.is_object() => agent,
        _ => return error("agent payload is required"),
    };

    let mut args = vec!["-o".into(), "BatchMode=yes".into()];
    if let Some(port) = config.get("port").and_then(Value::as_str).filter(|v| !v.is_empty()) {
        args.extend(["-p".into(), port.into()]);
    }
    args.extend([host.into(), "openclaw".into(), "buzz".into(), "enroll".into(), "--stdin".into()]);

    // Tests may provide a fake ssh executable. Production always uses the
    // user's normal ssh trust/agent configuration.
    let command = std::env::var_os("BUZZ_OPENCLAW_SSH").unwrap_or_else(|| "ssh".into());
    let mut child = match Command::new(command).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(_) => return error("could not start ssh"),
    };
    // Keep the existing enrollment wire version explicit while adding the
    // provider-only room selection needed by the OpenClaw importer. The
    // desktop's identity/relay fields are passed through unchanged.
    let remote_payload = json!({
        "version": 1,
        "agent": agent,
        "rooms": config.get("rooms").and_then(Value::as_str).unwrap_or_default(),
    });
    let payload = match serde_json::to_vec(&remote_payload) {
        Ok(mut payload) => { payload.push(b'\n'); payload },
        Err(_) => return error("could not encode enrollment payload"),
    };
    if let Some(mut stdin) = child.stdin.take() {
        if std::io::Write::write_all(&mut stdin, &payload).is_err() { return error("could not send enrollment payload"); }
    }
    let output = match child.wait_with_output() { Ok(output) => output, Err(_) => return error("ssh enrollment failed") };
    if !output.status.success() { return error("ssh enrollment failed"); }
    let response: Value = match serde_json::from_slice(&output.stdout) { Ok(response) => response, Err(_) => return error("OpenClaw returned invalid enrollment response") };
    if response.get("ok") != Some(&Value::Bool(true)) { return error("OpenClaw enrollment was rejected"); }
    match response.get("agent_id").and_then(Value::as_str).filter(|v| !v.is_empty()) {
        Some(agent_id) => json!({"ok": true, "agent_id": agent_id}),
        None => error("OpenClaw enrollment response missing agent_id"),
    }
}

fn respond(request: Value) -> Value {
    match request.get("op").and_then(Value::as_str) {
        Some("info") => info(),
        Some("enroll") if request.get("enrollment").and_then(|v| v.get("version")).and_then(Value::as_u64) == Some(1) => enroll(&request),
        Some("enroll") => error("unsupported enrollment version"),
        _ => error("unsupported operation"),
    }
}

fn main() {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() { std::process::exit(1); }
    let response = serde_json::from_str::<Value>(&input).map(respond).unwrap_or_else(|_| error("request is not valid JSON"));
    println!("{}", response);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn info_declares_one_time_v1_enrollment() {
        assert_eq!(info()["protocol_version"], 1);
        assert_eq!(info()["enrollment"]["one_time"], true);
    }
    #[test]
    fn rejects_missing_host_without_invoking_ssh() {
        let response = respond(json!({"op":"enroll", "enrollment":{"version":1}, "agent":{}}));
        assert_eq!(response["ok"], false);
        assert!(response["error"].as_str().unwrap().contains("host"));
    }
}
