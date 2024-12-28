/*
 * Copyright 2024 The Twelve-Factor Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
pub mod child;
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
