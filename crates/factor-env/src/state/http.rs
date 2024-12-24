use async_trait::async_trait;
use derive_new::new;
use url::Url;
#[cfg(feature = "mock")]
use wiremock::MockServer;

#[async_trait]
pub trait HttpClient: std::fmt::Debug {
    async fn request_get(&self, url: Url) -> String;
}

#[cfg(feature = "physical")]
#[async_trait]
impl HttpClient for reqwest::Client {
    async fn request_get(&self, url: Url) -> String {
        match self.get(url).send().await {
            Ok(response) => response.text().await.unwrap(),
            // TODO: handle errors properly
            Err(e) => panic!("Unexpected HTTP error: {:?}", e),
        }
    }
}

#[cfg(feature = "mock")]
#[derive(Debug, new)]
struct MockHttp {
    server: MockServer,
    client: reqwest::Client,
}

#[cfg(feature = "mock")]
#[async_trait]
impl HttpClient for MockHttp {
    async fn request_get(&self, url: Url) -> String {
        self.client.request_get(url).await
    }
}
