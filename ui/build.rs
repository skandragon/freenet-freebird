use std::process::Command;

fn cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let hash = cmd("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let date = cmd("date", &["-u", "+%Y-%m-%d"]).unwrap_or_default();
    // Monotonic build number for the update banner; 0 = no git = dev build
    // (the banner disables itself, see freebird_control::update_available).
    let number = cmd("git", &["rev-list", "--count", "HEAD"]).unwrap_or_else(|| "0".into());
    println!("cargo:rustc-env=BUILD_HASH={hash}");
    println!("cargo:rustc-env=BUILD_DATE={date}");
    println!("cargo:rustc-env=BUILD_NUMBER={number}");
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
