use derive_more::Debug;
use derive_new::new;
use http::Method;
use preinterpret::preinterpret;
use vfs::MemoryFS;
use wiremock::{matchers::method, Mock, MockBuilder, MockServer};

#[derive(Debug, new)]
pub struct MockStateBuilder {
    vars: rustc_hash::FxHashMap<String, String>,
    fs: MemoryFS,
    http: MockServer,
}

macro_rules! http_method {
    ($method:ident) => {
        pub async fn $method(self, handler: impl FnOnce(MockBuilder) -> Mock) -> Self {
            preinterpret! {
                let mock = handler(Mock::given(method(Method:: [!ident_upper_snake! $method])));
                self.http.register(mock).await;
                self
            }
        }
    };
}

impl MockStateBuilder {
    http_method!(get);
    http_method!(post);
    http_method!(put);
    http_method!(delete);
    http_method!(head);
    http_method!(patch);

    pub fn env_var(mut self, key: &str, value: &str) -> Self {
        let vars = &mut self.vars;
        vars.insert(key.to_string(), value.to_string());
        self
    }

    pub fn fs(mut self, setup: impl FnOnce(&mut MemoryFS)) -> Self {
        setup(&mut self.fs);
        self
    }
}
