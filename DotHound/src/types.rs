use std::{error::Error, fmt};
use url::Url;

#[derive(Clone, Debug)]
pub struct LoginInput {
    endpoint: Url,
}

impl LoginInput {
    pub fn new(endpoint: Url) -> Self {
        Self { endpoint }
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub fn safe_target(&self) -> String {
        safe_endpoint_label(&self.endpoint)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointValidationError {
    Empty,
    InvalidUrl(String),
    MissingHost,
    UnsupportedScheme(String),
}

impl fmt::Display for EndpointValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "login endpoint cannot be empty"),
            Self::InvalidUrl(reason) => {
                write!(formatter, "login endpoint is not a valid URL: {reason}")
            }
            Self::MissingHost => write!(formatter, "login endpoint must include a host"),
            Self::UnsupportedScheme(scheme) => {
                write!(
                    formatter,
                    "login endpoint must use http or https, not {scheme}"
                )
            }
        }
    }
}

impl Error for EndpointValidationError {}

pub fn parse_login_endpoint(raw_endpoint: &str) -> Result<Url, EndpointValidationError> {
    let trimmed_endpoint = raw_endpoint.trim();

    if trimmed_endpoint.is_empty() {
        return Err(EndpointValidationError::Empty);
    }

    let endpoint = Url::parse(trimmed_endpoint)
        .map_err(|error| EndpointValidationError::InvalidUrl(error.to_string()))?;

    match endpoint.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(EndpointValidationError::UnsupportedScheme(
                scheme.to_owned(),
            ));
        }
    }

    if endpoint.host_str().is_none() {
        return Err(EndpointValidationError::MissingHost);
    }

    Ok(endpoint)
}

pub fn safe_endpoint_label(endpoint: &Url) -> String {
    let host = endpoint.host_str().unwrap_or("<unknown-host>");
    let path = if endpoint.path().is_empty() {
        "/"
    } else {
        endpoint.path()
    };

    if endpoint.query().is_some() {
        format!("{host}{path}?<query-redacted>")
    } else {
        format!("{host}{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_and_https_login_endpoints() {
        let http_endpoint = parse_login_endpoint("http://localhost:8080/login").unwrap();
        let https_endpoint = parse_login_endpoint("https://example.test/auth").unwrap();

        assert_eq!(http_endpoint.scheme(), "http");
        assert_eq!(https_endpoint.scheme(), "https");
    }

    #[test]
    fn rejects_empty_login_endpoint() {
        let error = parse_login_endpoint("   ").unwrap_err();

        assert_eq!(error, EndpointValidationError::Empty);
    }

    #[test]
    fn rejects_unsupported_login_endpoint_scheme() {
        let error = parse_login_endpoint("ftp://example.test/login").unwrap_err();

        assert_eq!(
            error,
            EndpointValidationError::UnsupportedScheme("ftp".to_owned())
        );
    }

    #[test]
    fn safe_endpoint_label_redacts_query_string() {
        let endpoint = parse_login_endpoint("https://example.test/login?token=secret").unwrap();

        assert_eq!(
            safe_endpoint_label(&endpoint),
            "example.test/login?<query-redacted>"
        );
    }
}
