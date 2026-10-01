// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the actual CLI; no production settings, SMTP or database involved.
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Output};

struct PrivateFile(PathBuf);
impl PrivateFile {
    fn new(content: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("cc-native-{}.json", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path).unwrap().write_all(content).unwrap();
        Self(path)
    }
}
impl Drop for PrivateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_consolecrypt-server"));
    command.env_clear();
    command
}
fn assert_redacted_failure(output: Output, secret: &str) {
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
}

#[test]
fn bad_config_values_are_never_echoed_by_the_cli() {
    let secret = uuid::Uuid::new_v4().to_string();
    for key in [
        "CC_MAIL_TRANSPORT",
        "CC_SMTP_TLS",
        "CC_EVENT_BUS",
        "CC_LOG_FORMAT",
    ] {
        let mut settings = serde_json::json!({
            "CC_DATABASE_URL": "postgres://127.0.0.1/unused",
            "CC_MAIL_TRANSPORT": "smtp", "CC_SMTP_HOST": "smtp.example.invalid"
        });
        settings[key] = secret.clone().into();
        let file = PrivateFile::new(&serde_json::to_vec(&settings).unwrap());
        assert_redacted_failure(
            command().arg("--config").arg(&file.0).output().unwrap(),
            &secret,
        );
    }
}

#[test]
fn missing_file_does_not_fall_back_to_environment() {
    let secret = uuid::Uuid::new_v4().to_string();
    let path = std::env::temp_dir().join(&secret);
    let output = command()
        .env("CC_CONFIG_FILE", path)
        .arg("healthcheck")
        .output()
        .unwrap();
    assert_redacted_failure(output, &secret);
}

#[test]
fn healthcheck_uses_config_file_and_environment_override_without_database() {
    for use_env_override in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket
                            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                            .unwrap();
                        let mut request = [0; 256];
                        let size = socket.read(&mut request).unwrap();
                        assert!(request[..size].starts_with(b"GET /readyz HTTP/1.1"));
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "probe did not connect"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => panic!("test listener failed"),
                }
            }
        });
        let file_addr = if use_env_override {
            "127.0.0.1:0".to_owned()
        } else {
            addr.to_string()
        };
        let file = PrivateFile::new(
            &serde_json::to_vec(&serde_json::json!({"CC_LISTEN_ADDR":file_addr})).unwrap(),
        );
        let mut cmd = command();
        if use_env_override {
            cmd.env("CC_CONFIG_FILE", &file.0)
                .env("CC_LISTEN_ADDR", addr.to_string());
        } else {
            // Global flag works after the subcommand and wins over env path.
            cmd.env("CC_CONFIG_FILE", "/nonexistent-file");
        }
        cmd.arg("healthcheck");
        if !use_env_override {
            cmd.arg("--config").arg(&file.0);
        }
        let output = cmd.output().unwrap();
        assert!(output.status.success(), "config-based probe failed");
        server.join().unwrap();
    }
}
