use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum FactorError {
    #[snafu(display("{}", source))]
    #[snafu(context(false))]
    NotifyError {
        #[snafu(source)]
        source: notify::Error,
    },

    VfsError {
        source: vfs::error::VfsError,
        path: String,
    },
}
