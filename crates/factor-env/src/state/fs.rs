use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use factor_error::{FactorError, VfsSnafu};
use notify::Event as NotifyEvent;

pub type OnChange<T> = Arc<dyn Fn(T) + Send + Sync>;

/// This module
trait NotifiableFs {
    fn watch(
        &self,
        path: &Path,
        handler: impl ReadWatchableFile,
        on_change: OnChange<String>,
    ) -> Result<(), FactorError>;
}

#[cfg(feature = "physical")]
use notify::{RecursiveMode, Watcher};
use snafu::ResultExt;
use vfs::{VfsError, VfsPath};

#[cfg(feature = "physical")]
struct NotifiablePhysicalFs(VfsPath);

#[cfg(feature = "physical")]
impl NotifiablePhysicalFs {
    pub fn new(fs: vfs::PhysicalFS) -> Self {
        Self(VfsPath::new(fs))
    }
}

#[cfg(feature = "physical")]
impl NotifiableFs for NotifiablePhysicalFs {
    fn watch(
        &self,
        path: &Path,
        handler: impl ReadWatchableFile,
        on_change: OnChange<String>,
    ) -> Result<(), FactorError> {
        let path_buf = path.to_owned();
        let vfs_path = self.0.join(path_buf.to_string_lossy()).context(VfsSnafu {
            path: path.display().to_string(),
        })?;

        let mut watcher =
            notify::recommended_watcher(move |res: Result<NotifyEvent, notify::Error>| {
                if let Ok(event) = res {
                    if handler.filter(&event) {
                        if let Ok(content) = vfs_path.read_to_string() {
                            on_change(handler.process(content));
                        }
                    }
                }
            })?;

        watcher.watch(Path::new("."), RecursiveMode::Recursive)?;

        Ok(())
    }
}

trait ReadWatchableFile: Send + Sync + 'static {
    fn filter(&self, event: &NotifyEvent) -> bool;
    fn process(&self, content: String) -> String;
}
