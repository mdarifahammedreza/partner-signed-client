//! Rust equivalent of examples/test-handoff-hmac.js and examples/test-handoff-ed25519.js.
//! Reads the same repo-root .env as the Node examples.
//!
//!   cargo run --example handoff -- hmac
//!   cargo run --example handoff -- ed25519

use std::env;
use std::fs;
use std::process::ExitCode;

use partner_signed_client::{HandoffOptions, HandoffResult, PartnerClient, SigningScheme};

fn main() -> ExitCode {
    // Load .env before the async runtime starts any threads (set_var is only sound single-threaded).
    load_env();

    let result = tokio::runtime::Runtime::new()
        .map_err(Into::into)
        .and_then(|runtime| runtime.block_on(run()));

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Request failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let scheme: SigningScheme = env::args().nth(1).as_deref().unwrap_or("hmac").parse()?;
    let prefix = match scheme {
        SigningScheme::Hmac => "HMAC",
        SigningScheme::Ed25519 => "ED25519",
    };

    let secret = match scheme {
        SigningScheme::Hmac => var("HMAC_SECRET")?,
        // .env can only carry the PEM with real newlines escaped as literal "\n".
        SigningScheme::Ed25519 => var("ED25519_PRIVATE_KEY_PEM")?.replace("\\n", "\n"),
    };

    let options = HandoffOptions::new(
        var("API_BASE_URL")?,
        scheme,
        secret,
        var(&format!("{prefix}_PARTNER_SLUG"))?,
        var(&format!("{prefix}_TEST_PARTNER_USER_ID"))?,
        var(&format!("{prefix}_TEST_PHONE_NUMBER"))?,
    );

    let response = PartnerClient::new().handoff(options).await?;

    println!("status: {}", response.status);
    if response.ok {
        if let Ok(result) = response.data_as::<HandoffResult>() {
            println!(
                "entryUrl: {} (expires in {}s)",
                result.entry_url, result.expires_in
            );
        }
    }
    match &response.json {
        Some(json) => println!("body: {}", serde_json::to_string_pretty(json)?),
        None => println!("body: {}", response.raw_body),
    }
    Ok(())
}

fn var(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(format!(
            "Missing env var {name} — copy .env.example to .env and fill it in"
        )),
    }
}

/// Minimal .env loader — walks up from the working directory to the first .env; real env vars win.
fn load_env() {
    let Ok(cwd) = env::current_dir() else { return };
    let Some(contents) = cwd
        .ancestors()
        .find_map(|dir| fs::read_to_string(dir.join(".env")).ok())
    else {
        return;
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || env::var_os(key).is_some() {
            continue;
        }
        // SAFETY: runs at the top of `main`, before any other thread exists.
        unsafe { env::set_var(key, value.trim()) };
    }
}
