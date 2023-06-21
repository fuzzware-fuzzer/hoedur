pub trait LogError<T> {
    fn log_error(self) -> Option<T>;
}

impl<T> LogError<T> for Result<T, anyhow::Error> {
    fn log_error(self) -> Option<T> {
        match self {
            Ok(data) => Some(data),
            Err(e) => {
                log::error!("{}", e);
                None
            }
        }
    }
}
