use crate::{
    ca::CertificateAuthority,
    capture::{
        CaptureOptions, CaptureStore, CapturedExchange, CapturedRequest, CapturedResponse,
        ExchangeKind, capture_body, capture_headers, content_length, unix_timestamp_millis,
    },
};
use rustls::pki_types::ServerName;
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::oneshot,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use url::Url;

const MAX_HEADER_BYTES: usize = 128 * 1024;
const MAX_FORWARD_BODY_BYTES: usize = 10 * 1024 * 1024;

// ── ProxyServer ────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ProxyServer {
    listener: TcpListener,
    capture_store: CaptureStore,
    options: CaptureOptions,
    ca: CertificateAuthority,
}

impl ProxyServer {
    pub async fn bind(
        address: impl ToSocketAddrs,
        capture_store: CaptureStore,
        options: CaptureOptions,
        ca: CertificateAuthority,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;

        Ok(Self {
            listener,
            capture_store,
            options,
            ca,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) -> io::Result<()> {
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (client, client_addr) = accepted?;
                    let capture_store = self.capture_store.clone();
                    let options = self.options.clone();
                    let ca = self.ca.clone();

                    tokio::spawn(async move {
                        if let Err(error) = handle_client(client, client_addr, capture_store, options, ca).await {
                            eprintln!("Proxy connection error from {client_addr}: {error}");
                        }
                    });
                }
                _ = &mut shutdown => break,
            }
        }

        Ok(())
    }
}

// ── top-level connection handler ───────────────────────────────────

async fn handle_client(
    mut client: TcpStream,
    client_addr: SocketAddr,
    capture_store: CaptureStore,
    options: CaptureOptions,
    ca: CertificateAuthority,
) -> io::Result<()> {
    let (head, buffered_body) = read_http_head(&mut client).await?;
    let request = parse_request_head(&head)?;

    if request.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect_tunnel(client, client_addr, capture_store, options, ca, request).await
    } else {
        handle_http_request(
            client,
            client_addr,
            capture_store,
            options,
            request,
            buffered_body,
        )
        .await
    }
}

// ── HTTPS CONNECT tunnel with MITM ─────────────────────────────────

async fn handle_connect_tunnel(
    mut client: TcpStream,
    client_addr: SocketAddr,
    capture_store: CaptureStore,
    options: CaptureOptions,
    ca: CertificateAuthority,
    request: ParsedRequestHead,
) -> io::Result<()> {
    let started_at = unix_timestamp_millis();
    let exchange_id = capture_store.next_exchange_id();

    // Parse target: "example.com:443"
    let hostname = request
        .target
        .rsplit_once(':')
        .map(|(host, _port)| host)
        .unwrap_or(&request.target);

    // ── Record the CONNECT exchange ────────────────────────────────
    let notes = vec![
        "HTTPS CONNECT tunnel – MITM enabled. Decrypted exchanges follow as separate HTTP captures."
            .to_owned(),
    ];

    // Generate a per-host certificate signed by our CA.
    let server_config = ca.server_config_for_host(hostname)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Tell the client the tunnel is established.
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    capture_store.record_exchange(CapturedExchange {
        id: exchange_id,
        kind: ExchangeKind::HttpsTunnel,
        started_at_unix_ms: started_at,
        finished_at_unix_ms: unix_timestamp_millis(),
        client_addr: client_addr.to_string(),
        request: CapturedRequest {
            method: request.method,
            target: request.target.clone(),
            version: request.version,
            headers: capture_headers(&request.headers, &options),
            body: None,
        },
        response: Some(CapturedResponse {
            status_code: 200,
            reason: "Connection Established".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            body: None,
        }),
        notes,
    });

    // ── TLS handshake on the client side ───────────────────────────
    let client_tls = match acceptor.accept(client).await {
        Ok(tls_stream) => tokio_rustls::TlsStream::Server(tls_stream),
        Err(error) => {
            // Client may not trust our CA; fallback is not possible here
            // because we already sent 200. Just log and close.
            eprintln!(
                "MITM TLS handshake failed for {hostname} (client didn't trust DotHound CA?): {error}"
            );
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, error));
        }
    };

    // ── Connect to the real upstream server ────────────────────────
    let upstream_addr = format!("{hostname}:443");
    let upstream_tcp = TcpStream::connect(&upstream_addr).await?;

    let client_config = CertificateAuthority::upstream_client_config()?;
    let connector = TlsConnector::from(Arc::new(client_config));

    let server_name = ServerName::try_from(hostname.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let server_tls =
        tokio_rustls::TlsStream::Client(connector.connect(server_name, upstream_tcp).await?);

    // ── MITM loop: proxy decrypted HTTP exchanges ──────────────────
    mitm_proxy_loop(
        client_tls,
        server_tls,
        client_addr,
        capture_store,
        options,
        hostname.to_owned(),
    )
    .await
}

/// Read HTTP requests from the (decrypted) client TLS stream, forward
/// them to the upstream server, capture everything, and forward responses
/// back to the client.  Loops until the connection is closed.
async fn mitm_proxy_loop(
    mut client_tls: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    mut server_tls: tokio_rustls::TlsStream<tokio::net::TcpStream>,
    client_addr: SocketAddr,
    capture_store: CaptureStore,
    options: CaptureOptions,
    hostname: String,
) -> io::Result<()> {
    loop {
        match proxy_one_tls_exchange(
            &mut client_tls,
            &mut server_tls,
            client_addr,
            &capture_store,
            &options,
            &hostname,
        )
        .await
        {
            Ok(()) => {
                // Successfully proxied one exchange; continue to next.
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                // Client or server closed the connection – normal.
                break Ok(());
            }
            Err(error) => {
                eprintln!("MITM exchange error for {hostname}: {error}");
                break Err(error);
            }
        }
    }
}

/// Proxy a single HTTP request-response exchange over already-established
/// TLS streams (client side decrypted, server side encrypted).
async fn proxy_one_tls_exchange(
    client_tls: &mut tokio_rustls::TlsStream<TcpStream>,
    server_tls: &mut tokio_rustls::TlsStream<TcpStream>,
    client_addr: SocketAddr,
    capture_store: &CaptureStore,
    options: &CaptureOptions,
    hostname: &str,
) -> io::Result<()> {
    // 1. Read request from client
    let (req_head, req_buffered_body) = read_http_head(client_tls).await?;
    let request = parse_request_head(&req_head)?;
    let request_body = read_body(client_tls, &request.headers, req_buffered_body).await?;

    let started_at = unix_timestamp_millis();
    let exchange_id = capture_store.next_exchange_id();

    // 2. Build origin-form request
    let target_url = resolve_http_target_with_scheme(&request, hostname, "https")?;
    let origin_target = origin_form_target(&target_url);
    let outgoing_head = build_origin_form_request(&request, &origin_target);

    // 3. Forward to server
    server_tls.write_all(&outgoing_head).await?;
    server_tls.write_all(&request_body).await?;

    // 4. Read response from server
    let (resp_head, resp_buffered_body) = read_http_head(server_tls).await?;
    let response = parse_response_head(&resp_head)?;
    let response_body =
        read_response_body(server_tls, &response.headers, resp_buffered_body).await?;

    // 5. Forward to client
    client_tls.write_all(&resp_head).await?;
    client_tls.write_all(&response_body).await?;

    // 6. Record
    let notes = vec!["Decrypted HTTPS exchange captured via MITM.".to_owned()];

    capture_store.record_exchange(CapturedExchange {
        id: exchange_id,
        kind: ExchangeKind::Http,
        started_at_unix_ms: started_at,
        finished_at_unix_ms: unix_timestamp_millis(),
        client_addr: client_addr.to_string(),
        request: CapturedRequest {
            method: request.method,
            target: target_url.to_string(),
            version: request.version,
            headers: capture_headers(&request.headers, options),
            body: capture_body(&request.headers, &request_body, options),
        },
        response: Some(CapturedResponse {
            status_code: response.status_code,
            reason: response.reason,
            version: response.version,
            headers: capture_headers(&response.headers, options),
            body: capture_body(&response.headers, &response_body, options),
        }),
        notes,
    });

    Ok(())
}

// ── plain HTTP (non-CONNECT) handler ───────────────────────────────

async fn handle_http_request(
    mut client: TcpStream,
    client_addr: SocketAddr,
    capture_store: CaptureStore,
    options: CaptureOptions,
    request: ParsedRequestHead,
    buffered_body: Vec<u8>,
) -> io::Result<()> {
    let started_at = unix_timestamp_millis();
    let exchange_id = capture_store.next_exchange_id();
    let mut notes = Vec::new();
    let request_body = read_body(&mut client, &request.headers, buffered_body).await?;
    let target_url = resolve_http_target(&request)?;
    let authority = target_authority(&target_url)?;
    let origin_target = origin_form_target(&target_url);
    let mut server = TcpStream::connect(&authority).await?;
    let outgoing_head = build_origin_form_request(&request, &origin_target);

    server.write_all(&outgoing_head).await?;
    server.write_all(&request_body).await?;

    let (response_head, response_buffered_body) = read_http_head(&mut server).await?;
    let response = parse_response_head(&response_head)?;
    let response_body =
        read_response_body(&mut server, &response.headers, response_buffered_body).await?;

    client.write_all(&response_head).await?;
    client.write_all(&response_body).await?;

    if target_url.scheme() == "http" {
        notes.push("Full HTTP request/response captured through proxy.".to_owned());
    }

    capture_store.record_exchange(CapturedExchange {
        id: exchange_id,
        kind: ExchangeKind::Http,
        started_at_unix_ms: started_at,
        finished_at_unix_ms: unix_timestamp_millis(),
        client_addr: client_addr.to_string(),
        request: CapturedRequest {
            method: request.method,
            target: target_url.to_string(),
            version: request.version,
            headers: capture_headers(&request.headers, &options),
            body: capture_body(&request.headers, &request_body, &options),
        },
        response: Some(CapturedResponse {
            status_code: response.status_code,
            reason: response.reason,
            version: response.version,
            headers: capture_headers(&response.headers, &options),
            body: capture_body(&response.headers, &response_body, &options),
        }),
        notes,
    });

    Ok(())
}

// ── generic I/O helpers (work with TcpStream or TlsStream) ─────────

async fn read_http_head(
    stream: &mut (impl AsyncReadExt + Unpin),
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];

    loop {
        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP headers completed",
            ));
        }

        bytes.extend_from_slice(&buffer[..bytes_read]);

        if bytes.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP header block exceeded capture limit",
            ));
        }

        if let Some(header_end) = find_header_end(&bytes) {
            let buffered_body = bytes.split_off(header_end + 4);
            return Ok((bytes, buffered_body));
        }
    }
}

async fn read_body(
    stream: &mut (impl AsyncReadExt + Unpin),
    headers: &[(String, String)],
    mut buffered_body: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let Some(length) = content_length(headers) else {
        return Ok(buffered_body);
    };

    if length > MAX_FORWARD_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP body exceeded forwarding limit",
        ));
    }

    if buffered_body.len() > length {
        buffered_body.truncate(length);
    }

    while buffered_body.len() < length {
        let remaining = length - buffered_body.len();
        let mut chunk = vec![0; remaining.min(8192)];
        let bytes_read = stream.read(&mut chunk).await?;

        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP body completed",
            ));
        }

        buffered_body.extend_from_slice(&chunk[..bytes_read]);
    }

    Ok(buffered_body)
}

async fn read_response_body(
    stream: &mut (impl AsyncReadExt + Unpin),
    headers: &[(String, String)],
    buffered_body: Vec<u8>,
) -> io::Result<Vec<u8>> {
    if content_length(headers).is_some() {
        return read_body(stream, headers, buffered_body).await;
    }

    read_until_close(stream, buffered_body).await
}

async fn read_until_close(
    stream: &mut (impl AsyncReadExt + Unpin),
    mut buffered_body: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut buffer = [0; 8192];

    loop {
        if buffered_body.len() > MAX_FORWARD_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response body exceeded forwarding limit",
            ));
        }

        let bytes_read = stream.read(&mut buffer).await?;

        if bytes_read == 0 {
            break;
        }

        buffered_body.extend_from_slice(&buffer[..bytes_read]);
    }

    Ok(buffered_body)
}

// ── HTTP parsing ───────────────────────────────────────────────────

fn parse_request_head(head: &[u8]) -> io::Result<ParsedRequestHead> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request method"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request target"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request version"))?;

    Ok(ParsedRequestHead {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers: parse_headers(lines),
    })
}

fn parse_response_head(head: &[u8]) -> io::Result<ParsedResponseHead> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing response version"))?;
    let status_code = status_parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing status code"))?
        .parse::<u16>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let reason = status_parts.next().unwrap_or_default();

    Ok(ParsedResponseHead {
        version: version.to_owned(),
        status_code,
        reason: reason.to_owned(),
        headers: parse_headers(lines),
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    lines
        .filter_map(|line| {
            if line.is_empty() {
                return None;
            }

            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

fn resolve_http_target(request: &ParsedRequestHead) -> io::Result<Url> {
    if let Ok(url) = Url::parse(&request.target) {
        return Ok(url);
    }

    let host = crate::capture::header_value(&request.headers, "host")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing Host header"))?;
    Url::parse(&format!("http://{host}{}", request.target))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Like `resolve_http_target` but for decrypted HTTPS exchanges where
/// we already know the hostname and scheme.
fn resolve_http_target_with_scheme(
    request: &ParsedRequestHead,
    hostname: &str,
    scheme: &str,
) -> io::Result<Url> {
    // Origin-form requests (path + optional query) are the norm inside
    // a TLS tunnel.
    let path = &request.target;
    Url::parse(&format!("{scheme}://{hostname}{path}"))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn target_authority(url: &Url) -> io::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "target URL has no port"))?;

    Ok(format!("{host}:{port}"))
}

fn origin_form_target(url: &Url) -> String {
    let mut target = url.path().to_owned();

    if target.is_empty() {
        target.push('/');
    }

    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }

    target
}

fn build_origin_form_request(request: &ParsedRequestHead, origin_target: &str) -> Vec<u8> {
    let mut outgoing = format!(
        "{} {} {}\r\n",
        request.method, origin_target, request.version
    );

    for (name, value) in &request.headers {
        if should_skip_forwarded_header(name) {
            continue;
        }

        outgoing.push_str(name);
        outgoing.push_str(": ");
        outgoing.push_str(value);
        outgoing.push_str("\r\n");
    }

    outgoing.push_str("Connection: close\r\n\r\n");
    outgoing.into_bytes()
}

fn should_skip_forwarded_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "proxy-connection" | "proxy-authorization" | "connection" | "keep-alive"
    )
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

// ── types ──────────────────────────────────────────────────────────

#[derive(Debug)]
struct ParsedRequestHead {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
}

#[derive(Debug)]
struct ParsedResponseHead {
    version: String,
    status_code: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_http_head_parses_simple_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (head, leftover) = read_http_head(&mut &data[..]).await.unwrap();

        let request = parse_request_head(&head).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(request.headers.len(), 1);
        assert!(leftover.is_empty());
    }

    #[test]
    fn find_header_end_detects_boundary() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";
        let pos = find_header_end(data).unwrap();
        assert_eq!(pos, 33); // position of \r\n\r\n
    }
}
