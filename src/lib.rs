pub mod child;
pub mod dirs;
pub mod env;
pub mod identity;
pub mod ngrok;
pub mod proxy;
pub mod server;

#[test]
fn check_code_formatting() {
    use xshell::cmd;

    let sh = xshell::Shell::new().unwrap();

    let res = cmd!(sh, "cargo +nightly fmt --check").run();
    if res.is_err() {
        let _ = cmd!(sh, "cargo +nightly fmt").run();
    }

    // fail test intentionally if formatting occurs so that the test will fail in CI
    res.unwrap();
}
