//! The binary never prints the Redis URL, which carries the Redis auth token.

use std::process::{Command, Output};

const TOKEN: &str = "s3cr3t-token";

fn serve(args: &[&str], redis_url: &str) -> (Output, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ownership-gateway"))
        .arg("serve")
        .args(args)
        .env("OWNERSHIP_GATEWAY_REDIS_URL", redis_url)
        .output()
        .unwrap();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output, printed)
}

#[test]
fn help_does_not_print_the_redis_url_from_the_environment() {
    let (output, printed) = serve(&["--help"], &format!("rediss://:{TOKEN}@cache:6379"));
    assert!(output.status.success(), "{printed}");
    assert!(printed.contains("OWNERSHIP_GATEWAY_REDIS_URL"), "{printed}");
    assert!(!printed.contains(TOKEN), "{printed}");
}

#[test]
fn a_rejected_redis_url_is_not_printed() {
    let (output, printed) = serve(&[], &format!("redis://:{TOKEN}@cache:6379"));
    assert!(!output.status.success());
    assert!(printed.contains("must use rediss://"), "{printed}");
    assert!(!printed.contains(TOKEN), "{printed}");
}
