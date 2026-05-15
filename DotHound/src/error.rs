use std::error::Error;

pub type DothoundResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
