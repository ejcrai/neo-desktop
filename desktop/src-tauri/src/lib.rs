//! NEO Desktop Native Shell (Tauri v2 + Rust).
//!
//! Architecture & Security Contract:
//! 1. 100% of NEO's R9 core and H/V packs stay in Hetzner Cloud; zero core IP travels inside this binary.
//! 2. User BYOK API Keys are stored exclusively in the OS native keychain (`keyring` crate: Windows Credential Manager,
//!    macOS Keychain, Linux Secret Service) and are NEVER sent to Hetzner.
//! 3. Detects and invokes local compute (`Ollama` :11434, `LM Studio` :1234, `ComfyUI` :8188) and scoped user workspace folders.
//! 4. Native System Tray (`tray-icon`) and Single Instance (`tauri-plugin-single-instance`), zero background zombie processes on exit.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, State, WindowEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const KEYRING_SERVICE: &str = "cloud.neo.desktop";
const DEFAULT_OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const KNOWN_PROVIDERS: &[&str] = &[
    "chatgpt_oauth",
    "github_copilot",
    "glm_minimax_kimi",
    "glm_minimax_kimi:zai",
    "glm_minimax_kimi:minimax",
    "glm_minimax_kimi:kimi",
    "claude_api",
    "gemini_ai_studio",
    "grok_xai",
    "openrouter",
    "composio",
];

static ACTIVE_LOCAL_TASKS: AtomicUsize = AtomicUsize::new(0);

pub struct DesktopState {
    pub workspace_dir: Mutex<Option<PathBuf>>,
    pub pending_oauth: tokio::sync::Mutex<Option<(tokio::net::TcpListener, String)>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalStepRequest {
    pub provider: String,
    pub model: String,
    pub system: String,
    pub prompt: String,
    pub max_tokens: Option<u32>,
    pub reasoning_effort: Option<String>,
    pub candidates: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceFileOpRequest {
    pub op: String,
    pub rel_path: Option<String>,
    pub content: Option<String>,
}

fn mask_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() > 8 {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}••••{}", prefix, suffix)
    } else if !chars.is_empty() {
        "••••".to_string()
    } else {
        String::new()
    }
}

fn read_keyring(provider: &str) -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, provider).ok()?;
    match entry.get_password() {
        Ok(val) if !val.trim().is_empty() => Some(val.trim().to_string()),
        _ => None,
    }
}

#[tauri::command]
fn save_local_key(provider: String, api_key: String) -> Result<bool, String> {
    let p = provider.trim();
    let k = api_key.trim();
    if p.is_empty() || k.is_empty() {
        return Err("Provider and API key are required".to_string());
    }
    let entry = keyring::Entry::new(KEYRING_SERVICE, p).map_err(|e| e.to_string())?;
    entry.set_password(k).map_err(|e| e.to_string())?;
    Ok(true)
}

#[tauri::command]
fn delete_local_key(provider: String) -> Result<bool, String> {
    let p = provider.trim();
    if p.is_empty() {
        return Ok(false);
    }
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, p) {
        let _ = entry.delete_credential();
    }
    Ok(true)
}

#[tauri::command]
fn list_local_keys_status() -> Result<Value, String> {
    let mut map = serde_json::Map::new();
    for &pid in KNOWN_PROVIDERS {
        if let Some(secret) = read_keyring(pid) {
            let masked = mask_secret(&secret);
            let base_id = pid.split(':').next().unwrap_or(pid);
            map.insert(
                base_id.to_string(),
                json!({
                    "configured": true,
                    "masked": masked,
                }),
            );
        } else {
            let base_id = pid.split(':').next().unwrap_or(pid);
            if !map.contains_key(base_id) {
                map.insert(
                    base_id.to_string(),
                    json!({
                        "configured": false,
                        "masked": "",
                    }),
                );
            }
        }
    }
    Ok(Value::Object(map))
}

#[tauri::command]
async fn probe_local_compute(state: State<'_, DesktopState>) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(600))
        .build()
        .map_err(|e| e.to_string())?;

    let mut ollama_ok = false;
    let mut ollama_models: Vec<String> = Vec::new();
    if let Ok(resp) = client.get("http://127.0.0.1:11434/api/tags").send().await {
        if resp.status().is_success() {
            ollama_ok = true;
            if let Ok(body) = resp.json::<Value>().await {
                if let Some(arr) = body.get("models").and_then(|m| m.as_array()) {
                    for item in arr {
                        if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                            ollama_models.push(name.to_string());
                        }
                    }
                }
            }
        }
    }

    let lmstudio_ok = match client.get("http://127.0.0.1:1234/v1/models").send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    };

    let comfy_ok = match client.get("http://127.0.0.1:8188/system_stats").send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    };

    let ws_dir = state
        .workspace_dir
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|p| p.to_string_lossy().to_string()));

    Ok(json!({
        "ollama": {
            "connected": ollama_ok,
            "url": "http://127.0.0.1:11434",
            "models": ollama_models,
        },
        "lmstudio": {
            "connected": lmstudio_ok,
            "url": "http://127.0.0.1:1234",
        },
        "comfyui": {
            "connected": comfy_ok,
            "url": "http://127.0.0.1:8188",
        },
        "workspace_dir": ws_dir,
    }))
}

#[tauri::command]
async fn execute_local_model_step(req: LocalStepRequest) -> Result<Value, String> {
    ACTIVE_LOCAL_TASKS.fetch_add(1, Ordering::SeqCst);
    let res = execute_local_model_step_inner(req).await;
    ACTIVE_LOCAL_TASKS.fetch_sub(1, Ordering::SeqCst);
    res
}

async fn execute_local_model_step_inner(req: LocalStepRequest) -> Result<Value, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| e.to_string())?;

    let pid = req.provider.trim().to_lowercase();
    let max_tok = req.max_tokens.unwrap_or(2048);

    if pid == "ollama" {
        let model = if req.model.trim().is_empty() {
            "llama3.2".to_string()
        } else {
            req.model.trim().to_string()
        };
        let resp = client
            .post("http://127.0.0.1:11434/api/chat")
            .json(&json!({
                "model": model,
                "stream": false,
                "messages": [
                    { "role": "system", "content": req.system },
                    { "role": "user", "content": req.prompt }
                ]
            }))
            .send()
            .await
            .map_err(|e| format!("Ollama connection error: {}", e))?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("Ollama HTTP {}: {}", status, body));
        }
        let text = body
            .pointer("/message/content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        return Ok(json!({
            "ok": true,
            "text": text,
            "provider": "ollama",
            "model": model,
        }));
    }

    if pid == "claude_api" {
        let key = read_keyring("claude_api")
            .ok_or_else(|| "No Anthropic API key found in OS keyring".to_string())?;
        let model = if req.model.trim().is_empty() {
            "claude-opus-5-5".to_string()
        } else {
            req.model.trim().to_string()
        };
        let resp = client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": model,
                "max_tokens": max_tok,
                "system": req.system,
                "messages": [{ "role": "user", "content": req.prompt }]
            }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let body: Value = resp.json().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(format!("Anthropic HTTP {}: {}", status, body));
        }
        let mut out = String::new();
        if let Some(arr) = body.get("content").and_then(|c| c.as_array()) {
            for block in arr {
                if let Some(t) = block.get("text").and_then(|t| t.as_str()) {
                    out.push_str(t);
                }
            }
        }
        return Ok(json!({
            "ok": true,
            "text": out.trim(),
            "provider": "claude_api",
            "model": model,
        }));
    }

    // T19 · Single unified ChatGPT / Codex / OpenAI adapter calling `/v1/responses` without temperature, top_p, or max_tokens,
    // with automatic downward model fallback (T04) across `req.candidates` (`gpt-6.2-astra` -> `gpt-6.2-sol` -> `gpt-6-luna` -> `gpt-6.1-terra`).
    if pid == "chatgpt_oauth" || pid == "openai" || pid == "codex" {
        let key = read_keyring("chatgpt_oauth")
            .or_else(|| read_keyring(&pid))
            .ok_or_else(|| "No ChatGPT / OpenAI token or API key configured in OS keyring".to_string())?;
        let client_id = std::env::var("NEO_OPENAI_CLIENT_ID")
            .or_else(|_| std::env::var("OPENAI_CODEX_CLIENT_ID"))
            .unwrap_or_else(|_| DEFAULT_OPENAI_CLIENT_ID.to_string());
        let primary = if req.model.trim().is_empty() {
            "gpt-6.2-sol".to_string()
        } else {
            req.model.trim().to_string()
        };
        let mut try_models: Vec<String> = req.candidates.clone().unwrap_or_default();
        if !try_models.contains(&primary) {
            try_models.insert(0, primary.clone());
        }
        for fallback_m in ["gpt-6.2-sol", "gpt-6-luna", "gpt-6.1-terra"] {
            let s = fallback_m.to_string();
            if !try_models.contains(&s) {
                try_models.push(s);
            }
        }
        let effort = req.reasoning_effort.clone().unwrap_or_else(|| "low".to_string());
        let mut last_err = String::new();
        for m_try in try_models {
            let mut payload = json!({
                "model": m_try,
                "instructions": req.system,
                "input": req.prompt,
            });
            if matches!(effort.as_str(), "low" | "medium" | "high") {
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("reasoning".to_string(), json!({ "effort": effort }));
                }
            }
            let resp = client
                .post("https://api.openai.com/v1/responses")
                .bearer_auth(&key)
                .header("x-openai-client-id", &client_id)
                .json(&payload)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            if status.is_success() {
                let mut out_text = body
                    .get("output_text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if out_text.is_empty() {
                    if let Some(arr) = body.get("output").and_then(|v| v.as_array()) {
                        let mut parts: Vec<String> = Vec::new();
                        for item in arr {
                            if let Some(carr) = item.get("content").and_then(|c| c.as_array()) {
                                for c in carr {
                                    if let Some(t) = c.get("text").and_then(|t| t.as_str()) {
                                        parts.push(t.to_string());
                                    }
                                }
                            }
                        }
                        out_text = parts.join("\n").trim().to_string();
                    }
                }
                return Ok(json!({
                    "ok": true,
                    "text": out_text,
                    "provider": pid,
                    "model": m_try,
                    "fallback_applied": m_try != primary,
                }));
            }
            last_err = format!("OpenAI /v1/responses HTTP {} for {}: {}", status, m_try, body);
            if status.as_u16() != 403 && status.as_u16() != 404 {
                break;
            }
        }
        return Err(last_err);
    }

    // OpenAI-compatible BYOK endpoints (Gemini AI Studio, Grok xAI, GLM/MiniMax/Kimi, GitHub Copilot, LM Studio)
    let (base_url, default_model, key_opt) = match pid.as_str() {
        "gemini_ai_studio" => (
            "https://generativelanguage.googleapis.com/v1beta/openai",
            "gemini-4-argon",
            read_keyring("gemini_ai_studio"),
        ),
        "grok_xai" => (
            "https://api.x.ai/v1",
            "grok-3-mini",
            read_keyring("grok_xai"),
        ),
        "github_copilot" => (
            "https://models.inference.ai.azure.com",
            "gpt-4o",
            read_keyring("github_copilot"),
        ),
        "glm_minimax_kimi" => {
            if let Some(k) = read_keyring("glm_minimax_kimi:minimax") {
                ("https://api.minimax.chat/v1", "MiniMax-Text-01", Some(k))
            } else if let Some(k) = read_keyring("glm_minimax_kimi:kimi") {
                ("https://api.moonshot.cn/v1", "moonshot-v1-8k", Some(k))
            } else {
                (
                    "https://open.bigmodel.cn/api/paas/v4",
                    "glm-4.5",
                    read_keyring("glm_minimax_kimi:zai").or_else(|| read_keyring("glm_minimax_kimi")),
                )
            }
        }
        "lmstudio" => ("http://127.0.0.1:1234/v1", "local-model", Some("lm-studio".to_string())),
        _ => (
            "https://api.openai.com/v1",
            "gpt-4.1",
            read_keyring("chatgpt_oauth").or_else(|| read_keyring(&pid)),
        ),
    };

    let key = key_opt.ok_or_else(|| format!("No API key configured in OS keyring for {}", pid))?;
    let model = if req.model.trim().is_empty() {
        default_model.to_string()
    } else {
        req.model.trim().to_string()
    };

    let resp = client
        .post(format!("{}/chat/completions", base_url.trim_end_matches('/')))
        .bearer_auth(key)
        .json(&json!({
            "model": model,
            "messages": [
                { "role": "system", "content": req.system },
                { "role": "user", "content": req.prompt }
            ]
        }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("Provider {} HTTP {}: {}", pid, status, body));
    }
    let text = body
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    Ok(json!({
        "ok": true,
        "text": text,
        "provider": pid,
        "model": model,
    }))
}

#[tauri::command]
async fn pick_project_folder(
    app: AppHandle,
    state: State<'_, DesktopState>,
    initial_path: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let mut builder = app.dialog().file();
    if let Some(init) = initial_path {
        let p = PathBuf::from(&init);
        if p.is_dir() {
            builder = builder.set_directory(p);
        }
    }
    let picked = builder.blocking_pick_folder();
    if let Some(fp) = picked {
        if let Ok(path) = fp.into_path() {
            let canon = path.canonicalize().unwrap_or(path);
            let s = canon.to_string_lossy().to_string();
            if let Ok(mut guard) = state.workspace_dir.lock() {
                *guard = Some(canon);
            }
            return Ok(Some(s));
        }
    }
    Ok(None)
}

fn resolve_scoped_path(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return Err("Absolute paths are not allowed".to_string());
    }
    for comp in rel_path.components() {
        match comp {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("Path traversal outside the workspace folder is forbidden".to_string());
            }
            Component::Normal(os_str) => {
                let s = os_str.to_string_lossy();
                if s.starts_with('.') {
                    return Err("Hidden dotfiles cannot be accessed".to_string());
                }
            }
            Component::CurDir => {}
        }
    }
    let joined = root.join(rel_path);
    if joined.exists() {
        let canon_root = root.canonicalize().map_err(|e| e.to_string())?;
        let canon_target = joined.canonicalize().map_err(|e| e.to_string())?;
        if !canon_target.starts_with(&canon_root) {
            return Err("Symlink escape outside workspace is forbidden".to_string());
        }
    }
    Ok(joined)
}

#[tauri::command]
fn workspace_file_op(
    state: State<'_, DesktopState>,
    req: WorkspaceFileOpRequest,
) -> Result<Value, String> {
    let root = state
        .workspace_dir
        .lock()
        .map_err(|e| e.to_string())?
        .clone()
        .ok_or_else(|| "No local project folder has been authorized yet".to_string())?;

    let rel = req.rel_path.unwrap_or_default();
    match req.op.as_str() {
        "list" => {
            let target = if rel.trim().is_empty() {
                root.clone()
            } else {
                resolve_scoped_path(&root, &rel)?
            };
            let mut entries = Vec::new();
            for entry in fs::read_dir(target).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                entries.push(json!({ "name": name, "is_dir": is_dir }));
            }
            Ok(json!({ "entries": entries }))
        }
        "read" => {
            let target = resolve_scoped_path(&root, &rel)?;
            let content = fs::read_to_string(target).map_err(|e| e.to_string())?;
            Ok(json!({ "content": content }))
        }
        "write" => {
            let target = resolve_scoped_path(&root, &rel)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&target, req.content.unwrap_or_default()).map_err(|e| e.to_string())?;
            Ok(json!({ "written": true }))
        }
        _ => Err(format!("Unsupported workspace operation: {}", req.op)),
    }
}

#[tauri::command]
fn open_external_url(app: AppHandle, url: String) -> Result<bool, String> {
    let u = url.trim();
    if !u.starts_with("https://") && !u.starts_with("http://") {
        return Err("Unsupported URL scheme".to_string());
    }
    use tauri_plugin_shell::ShellExt;
    app.shell()
        .open(u, None)
        .map_err(|e| format!("Failed to open external URL: {}", e))?;
    Ok(true)
}

#[tauri::command]
async fn prepare_browser_oauth(state: State<'_, DesktopState>) -> Result<Value, String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind local OAuth callback: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to read OAuth callback port: {}", e))?
        .port();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let state_tok = format!("neo_{:x}_{:x}", nanos, std::process::id());
    {
        let mut guard = state.pending_oauth.lock().await;
        *guard = Some((listener, state_tok.clone()));
    }
    Ok(json!({
        "callback_url": format!("http://127.0.0.1:{}/auth/callback", port),
        "state": state_tok
    }))
}

#[tauri::command]
async fn complete_browser_oauth(
    app: AppHandle,
    state: State<'_, DesktopState>,
    auth_url: String,
) -> Result<Value, String> {
    let u = auth_url.trim().to_string();
    if !u.starts_with("https://") && !u.starts_with("http://") {
        return Err("Invalid OAuth URL".to_string());
    }
    let (listener, expected_state) = {
        let mut guard = state.pending_oauth.lock().await;
        guard.take().ok_or_else(|| "No pending OAuth flow".to_string())?
    };
    {
        use tauri_plugin_shell::ShellExt;
        app.shell()
            .open(&u, None)
            .map_err(|e| format!("Failed to open browser: {}", e))?;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("OAuth login timed out".to_string());
        }
        let (mut socket, _) = tokio::time::timeout(remaining, listener.accept())
            .await
            .map_err(|_| "OAuth login timed out".to_string())?
            .map_err(|e| format!("OAuth socket error: {}", e))?;
        let mut buf = Vec::with_capacity(16384);
        let mut chunk = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        let mut content_len: usize = 0;
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk))
                .await
                .unwrap_or(Ok(0))
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if header_end.is_none() {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(pos + 4);
                    let hdr = String::from_utf8_lossy(&buf[..pos]);
                    for line in hdr.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                content_len = v.trim().parse::<usize>().unwrap_or(0).min(65536);
                            }
                        }
                    }
                }
            }
            if let Some(he) = header_end {
                if buf.len() >= he + content_len {
                    break;
                }
            }
            if buf.len() > 65536 {
                break;
            }
        }
        let head_str = String::from_utf8_lossy(
            header_end.map(|he| &buf[..he]).unwrap_or(&buf[..]),
        )
        .to_string();
        if head_str.starts_with("OPTIONS ") {
            let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
            continue;
        }
        if head_str.starts_with("POST ") {
            let body_bytes = header_end.map(|he| &buf[he..]).unwrap_or(&[]);
            let parsed: Value = serde_json::from_slice(body_bytes).unwrap_or(Value::Null);
            let got_state = parsed
                .get("app_state")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if got_state != expected_state {
                let resp = "HTTP/1.1 403 Forbidden\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
                return Err("OAuth state mismatch".to_string());
            }
            let resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"ok\":true}";
            let _ = socket.write_all(resp.as_bytes()).await;
            show_main_window(&app);
            return Ok(parsed);
        }
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<!doctype html><html><body><p>NEO OAuth callback active.</p></body></html>";
        let _ = socket.write_all(resp.as_bytes()).await;
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(DesktopState {
            workspace_dir: Mutex::new(None),
            pending_oauth: tokio::sync::Mutex::new(None),
        })
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())   // T22: signed updates from the public releases (latest.json)
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // T22: at startup, look for a newer signed release (latest.json of the public releases); install it quietly.
            // Any failure (offline, no release yet) is ignored: the app always opens.
            {
                use tauri_plugin_updater::UpdaterExt;
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Ok(updater) = handle.updater() {
                        if let Ok(Some(update)) = updater.check().await {
                            let _ = update.download_and_install(|_, _| {}, || {}).await;
                        }
                    }
                });
            }
            let open_i = MenuItem::with_id(app, "open", "Abrir NEO", true, None::<&str>)?;
            let status_i = MenuItem::with_id(
                app,
                "status",
                "Estado de Mi PC (Ollama / ComfyUI)",
                true,
                None::<&str>,
            )?;
            let quit_i = MenuItem::with_id(app, "quit", "Salir completamente", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open_i, &status_i, &quit_i])?;

            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("NEO · Arnés Local & Cloud")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main_window(app),
                    "status" => {
                        show_main_window(app);
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.eval("window.location.assign('/app/studio?tab=conexiones');");
                        }
                    }
                    "quit" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                });

            if let Some(icon) = app.default_window_icon() {
                tray_builder = tray_builder.icon(icon.clone());
            }
            let _ = tray_builder.build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if ACTIVE_LOCAL_TASKS.load(Ordering::SeqCst) > 0 {
                    api.prevent_close();
                    let _ = window.hide();
                    #[cfg(desktop)]
                    {
                        use tauri_plugin_notification::NotificationExt;
                        let _ = window
                            .app_handle()
                            .notification()
                            .builder()
                            .title("NEO sigue trabajando en segundo plano")
                            .body("Minimizado a la bandeja del sistema mientras termina tu tarea local.")
                            .show();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            save_local_key,
            delete_local_key,
            list_local_keys_status,
            probe_local_compute,
            execute_local_model_step,
            pick_project_folder,
            workspace_file_op,
            open_external_url,
            prepare_browser_oauth,
            complete_browser_oauth,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NEO Desktop application");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_keyring_roundtrip() {
        let provider = "gemini_ai_studio";
        let _ = delete_local_key(provider.to_string());
        let saved = save_local_key(provider.to_string(), "AIzaTestLocalKeyringOnly12345".to_string());
        assert_eq!(saved, Ok(true));
        let status = list_local_keys_status().expect("list_local_keys_status failed");
        assert_eq!(
            status.get(provider).and_then(|v| v.get("configured")).and_then(|b| b.as_bool()),
            Some(true)
        );
        let deleted = delete_local_key(provider.to_string());
        assert_eq!(deleted, Ok(true));
        let status_after = list_local_keys_status().expect("list_local_keys_status after delete failed");
        assert_eq!(
            status_after.get(provider).and_then(|v| v.get("configured")).and_then(|b| b.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn test_workspace_file_op_rejects_traversal() {
        let tmp = std::env::temp_dir();
        let res = resolve_scoped_path(&tmp, "../outside.txt");
        assert!(res.is_err());
        let res_dot = resolve_scoped_path(&tmp, ".env");
        assert!(res_dot.is_err());
    }
}
