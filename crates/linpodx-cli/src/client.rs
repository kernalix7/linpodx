use anyhow::{anyhow, bail, Context, Result};
use linpodx_common::ipc::{
    Event, Method, Notification, ResponsePayload, RpcRequest, RpcResponse, ServerMessage,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

static NEXT_ID: AtomicI64 = AtomicI64::new(1);

/// One of the two underlying IPC transports — Unix socket (default) or WebSocket
/// (Phase 7 remote daemon). The CLI's high-level [`Client`] wraps either kind.
enum Transport {
    Unix {
        write: tokio::net::unix::OwnedWriteHalf,
        reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    },
    Remote(RemoteTransport),
}

pub struct Client {
    transport: Transport,
}

impl Client {
    /// Connect to the daemon over its local Unix socket.
    pub async fn connect(socket: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket).await.with_context(|| {
            format!(
                "could not connect to linpodx daemon at {}\n\
                 is it running? start it with `linpodx-daemon` in another terminal.",
                socket.display()
            )
        })?;
        let (read, write) = stream.into_split();
        Ok(Self {
            transport: Transport::Unix {
                write,
                reader: BufReader::new(read),
            },
        })
    }

    /// Connect to a remote daemon's WebSocket listener (Phase 7).
    /// `addr` may be a `ws://host:port[/path]`, `wss://host:port[/path]`, or a
    /// `host:port` shorthand (defaults to `ws://.../ipc`). `tls` carries optional
    /// PEM paths used when the URL is `wss://`.
    pub async fn connect_remote(addr: &str, token: &str, tls: TlsClientConfig) -> Result<Self> {
        let transport = RemoteTransport::connect(addr, token, tls).await?;
        Ok(Self {
            transport: Transport::Remote(transport),
        })
    }

    pub async fn call<T: serde::de::DeserializeOwned>(&mut self, method: Method) -> Result<T> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let req = RpcRequest::new(id, method);
        let payload = serde_json::to_string(&req).context("serializing request")?;

        let resp_line = match &mut self.transport {
            Transport::Unix { write, reader } => {
                let mut bytes = payload.into_bytes();
                bytes.push(b'\n');
                write.write_all(&bytes).await.context("writing request")?;
                write.flush().await.ok();
                let mut line = String::new();
                let n = reader
                    .read_line(&mut line)
                    .await
                    .context("reading response")?;
                if n == 0 {
                    bail!("daemon closed the connection without responding");
                }
                line
            }
            Transport::Remote(r) => r.send_recv(&payload).await?,
        };

        let resp: RpcResponse = serde_json::from_str(resp_line.trim_end())
            .with_context(|| format!("parsing response: {}", resp_line.trim_end()))?;

        match resp.payload {
            ResponsePayload::Success { result } => {
                serde_json::from_value(result).map_err(|e| anyhow!("decoding result: {e}"))
            }
            ResponsePayload::Error { error } => {
                bail!("daemon error (code {}): {}", error.code, error.message)
            }
        }
    }

    /// Read the next server-pushed `event` notification on this connection.
    /// Returns `Ok(None)` on EOF, `Err` on parse errors. Non-event server messages
    /// (e.g. approval_request notifications, spurious responses) are skipped.
    pub async fn next_event(&mut self) -> Result<Option<Event>> {
        loop {
            match self.next_server_message().await? {
                Some(ServerMessage::Notification(Notification { method, params, .. }))
                    if method == "event" =>
                {
                    let event: Event = serde_json::from_value(params)
                        .map_err(|e| anyhow!("decoding event payload: {e}"))?;
                    return Ok(Some(event));
                }
                Some(_) => continue,
                None => return Ok(None),
            }
        }
    }

    /// Read the next raw `ServerMessage` (Response or Notification of any method).
    /// Used by callers that need to demultiplex multiple notification kinds (e.g. the
    /// `approvals` subcommand handles `approval_request` while `events` handles `event`).
    pub async fn next_server_message(&mut self) -> Result<Option<ServerMessage>> {
        loop {
            let raw = match &mut self.transport {
                Transport::Unix { reader, .. } => {
                    let mut line = String::new();
                    let n = reader
                        .read_line(&mut line)
                        .await
                        .context("reading server message")?;
                    if n == 0 {
                        return Ok(None);
                    }
                    line
                }
                Transport::Remote(r) => match r.recv().await? {
                    Some(s) => s,
                    None => return Ok(None),
                },
            };
            let trimmed = raw.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let msg: ServerMessage = serde_json::from_str(trimmed)
                .with_context(|| format!("parsing server message: {trimmed}"))?;
            return Ok(Some(msg));
        }
    }

    /// `notify` variant for fire-and-forget calls.
    #[allow(dead_code)]
    pub async fn notify(&mut self, method: Method) -> Result<()> {
        let req = RpcRequest {
            jsonrpc: linpodx_common::ipc::JsonRpcVersion::V2,
            id: None,
            method,
        };
        let payload = serde_json::to_string(&req)?;
        match &mut self.transport {
            Transport::Unix { write, .. } => {
                let mut bytes = payload.into_bytes();
                bytes.push(b'\n');
                write.write_all(&bytes).await?;
                write.flush().await.ok();
            }
            Transport::Remote(r) => {
                r.send(&payload).await?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Remote (WebSocket) transport
// ---------------------------------------------------------------------------

use futures::stream::SplitSink;
use futures::stream::SplitStream;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, WsMessage>;
type WsSource = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// CLI-side TLS material for a `wss://` remote daemon connection. All three paths
/// are optional individually:
/// - `ca`: extra root CA to trust (e.g. when the daemon serves a self-signed cert).
/// - `client_cert` + `client_key`: required by mTLS-enabled daemons.
#[derive(Clone, Debug, Default)]
pub struct TlsClientConfig {
    pub ca: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

pub struct RemoteTransport {
    sink: WsSink,
    source: WsSource,
}

impl RemoteTransport {
    pub async fn connect(addr: &str, token: &str, tls: TlsClientConfig) -> Result<Self> {
        let url = normalize_remote_url(addr);
        let connector = if url.starts_with("wss://") {
            Some(Connector::Rustls(Arc::new(build_client_config(&tls)?)))
        } else {
            None
        };
        // Phase 14 — present the bearer token via the `Sec-WebSocket-Protocol`
        // subprotocol token (`Bearer.<token>`, dot-separated so the value
        // stays RFC 6455 §4.2 valid). Daemons that recognise this skip the
        // first-frame auth handshake; older daemons ignore the subprotocol
        // and fall through to the existing `{"auth":"<t>"}` envelope below.
        let request = build_ws_client_request(&url, token)?;
        let (ws, _resp) =
            tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector)
                .await
                .with_context(|| format!("connecting WebSocket to {url}"))?;
        let (mut sink, mut source) = ws.split();

        // Auth handshake.
        let auth = serde_json::json!({ "auth": token });
        sink.send(WsMessage::Text(auth.to_string()))
            .await
            .context("sending auth frame")?;
        let ack = source
            .next()
            .await
            .ok_or_else(|| anyhow!("remote daemon closed before auth ack"))?
            .context("reading auth ack")?;
        let ack_text = match ack {
            WsMessage::Text(s) => s,
            other => bail!("unexpected auth ack frame: {other:?}"),
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&ack_text).context("parsing auth ack")?;
        if parsed.get("auth").and_then(|v| v.as_str()) != Some("ok") {
            bail!(
                "remote daemon rejected token: {}",
                parsed
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or("auth failed")
            );
        }

        Ok(Self { sink, source })
    }

    async fn send(&mut self, payload: &str) -> Result<()> {
        self.sink
            .send(WsMessage::Text(payload.to_string()))
            .await
            .context("sending WS frame")
    }

    async fn send_recv(&mut self, payload: &str) -> Result<String> {
        self.send(payload).await?;
        let line = self
            .recv()
            .await?
            .ok_or_else(|| anyhow!("remote daemon closed mid-call"))?;
        Ok(line)
    }

    async fn recv(&mut self) -> Result<Option<String>> {
        loop {
            match self.source.next().await {
                Some(Ok(WsMessage::Text(s))) => return Ok(Some(s)),
                Some(Ok(WsMessage::Binary(_))) => continue,
                Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => continue,
                Some(Ok(WsMessage::Frame(_))) => continue,
                Some(Ok(WsMessage::Close(_))) | None => return Ok(None),
                Some(Err(e)) => return Err(anyhow!("WS read error: {e}")),
            }
        }
    }
}

/// Build a rustls `ClientConfig` for the `wss://` path. Honours an optional extra
/// CA cert (defaults to the system / webpki roots otherwise) and an optional client
/// cert + key pair for mTLS.
fn build_client_config(tls: &TlsClientConfig) -> Result<rustls::ClientConfig> {
    install_default_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca_path) = tls.ca.as_ref() {
        let pem = std::fs::read(ca_path)
            .with_context(|| format!("reading CA cert {}", ca_path.display()))?;
        let mut reader = std::io::Cursor::new(pem);
        for c in rustls_pemfile::certs(&mut reader).filter_map(|r| r.ok()) {
            roots.add(c).map_err(|e| anyhow!("adding CA cert: {e}"))?;
        }
    }
    // No --ca: leave the root store empty. Connections to public CAs would need the
    // user to plug `--ca /etc/ssl/certs/ca-certificates.crt` (or similar). For the
    // typical self-signed daemon case the user always supplies --ca.

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);

    let cfg = match (tls.client_cert.as_ref(), tls.client_key.as_ref()) {
        (Some(cert), Some(key)) => {
            let cert_chain = read_cert_chain(cert)?;
            let key_der = read_private_key(key)?;
            builder
                .with_client_auth_cert(cert_chain, key_der)
                .map_err(|e| anyhow!("with_client_auth_cert: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => bail!("--client-cert and --client-key must be supplied together"),
    };
    Ok(cfg)
}

fn read_cert_chain(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let pem =
        std::fs::read(path).with_context(|| format!("reading client cert {}", path.display()))?;
    let mut reader = std::io::Cursor::new(pem);
    let chain: Vec<_> = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    if chain.is_empty() {
        bail!("no certificate found in {}", path.display());
    }
    Ok(chain)
}

fn read_private_key(path: &Path) -> Result<rustls_pki_types::PrivateKeyDer<'static>> {
    let pem =
        std::fs::read(path).with_context(|| format!("reading client key {}", path.display()))?;
    let mut reader = std::io::Cursor::new(pem);
    if let Some(k) =
        rustls_pemfile::private_key(&mut reader).map_err(|e| anyhow!("parsing client key: {e}"))?
    {
        return Ok(k);
    }
    bail!("no private key found in {}", path.display())
}

fn install_default_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Phase 14 — build a `tungstenite::ClientRequestBuilder` carrying the bearer
/// token as the `Sec-WebSocket-Protocol: Bearer.<token>` subprotocol entry.
/// The dot separator keeps the protocol value RFC 6455 §4.2 compliant
/// (whitespace is disallowed in subprotocol tokens).
fn build_ws_client_request(
    url: &str,
    token: &str,
) -> Result<tokio_tungstenite::tungstenite::ClientRequestBuilder> {
    let uri: tokio_tungstenite::tungstenite::http::Uri = url
        .parse()
        .with_context(|| format!("parsing WebSocket URL {url}"))?;
    Ok(
        tokio_tungstenite::tungstenite::ClientRequestBuilder::new(uri)
            .with_sub_protocol(format!("Bearer.{token}")),
    )
}

/// Accept either a bare `host:port` (in which case we default to `ws://host:port/ipc`)
/// or a full `ws://`/`wss://` URL.
pub fn normalize_remote_url(addr: &str) -> String {
    let s = addr.trim();
    if s.starts_with("ws://") || s.starts_with("wss://") {
        if s.contains("/ipc") || s.split("://").nth(1).is_some_and(|r| r.contains('/')) {
            s.to_string()
        } else {
            format!("{}/ipc", s.trim_end_matches('/'))
        }
    } else {
        format!("ws://{s}/ipc")
    }
}

// ---------------------------------------------------------------------------
// Phase 12 — PTY WebSocket client (used by `linpodx exec -it`)
// ---------------------------------------------------------------------------

/// Build the `ws[s]://<host>/pty/<bridge_id>?token=<t>` URL by stripping the
/// trailing `/ipc` from the user-supplied remote URL (or leaving it bare for
/// the `host:port` shorthand) and appending `/pty/<id>` + query token.
pub fn build_pty_ws_url(remote: &str, bridge_id: &str, token: &str) -> String {
    let base = normalize_remote_url(remote);
    let trimmed = base.trim_end_matches("/ipc").trim_end_matches('/');
    let encoded_token = url_encode(token);
    format!("{trimmed}/pty/{bridge_id}?token={encoded_token}")
}

/// Minimal URL percent-encoder for the `token` query parameter. Encodes anything
/// outside the unreserved set per RFC 3986 (alphanum, `-_.~`).
fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// One end of the binary WebSocket bridge to a daemon-side PTY. Owns its own
/// connection separate from the JSON-RPC `Client`.
pub struct PtyWsClient {
    sink: WsSink,
    source: WsSource,
}

impl PtyWsClient {
    /// Open the WebSocket. The URL must already include `?token=<t>`; the daemon
    /// rejects unauthenticated `/pty/<id>` upgrades with HTTP 401.
    ///
    /// Phase 14 — when `token` is supplied, also presents
    /// `Sec-WebSocket-Protocol: Bearer.<token>` so daemons that prefer the
    /// header path don't have to crack open the URL query string. The query
    /// `?token=` stays on the URL for backward compatibility with daemons
    /// that don't recognise the subprotocol.
    pub async fn connect(url: &str, tls: TlsClientConfig, token: Option<&str>) -> Result<Self> {
        let connector = if url.starts_with("wss://") {
            Some(Connector::Rustls(Arc::new(build_client_config(&tls)?)))
        } else {
            None
        };
        let (ws, _resp) = match token {
            Some(t) => {
                let request = build_ws_client_request(url, t)?;
                tokio_tungstenite::connect_async_tls_with_config(request, None, false, connector)
                    .await
                    .with_context(|| format!("connecting PTY WebSocket to {url}"))?
            }
            None => tokio_tungstenite::connect_async_tls_with_config(url, None, false, connector)
                .await
                .with_context(|| format!("connecting PTY WebSocket to {url}"))?,
        };
        let (sink, source) = ws.split();
        Ok(Self { sink, source })
    }

    /// Bidirectional copy: stdin → ws (binary), ws → stdout. Returns when the
    /// WebSocket closes or stdin reaches EOF (Ctrl-D, /dev/null redirect, etc).
    pub async fn proxy_stdio(&mut self) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();

        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                // Read from stdin (raw bytes — caller has put the terminal in raw mode).
                read = stdin.read(&mut buf) => {
                    match read {
                        Ok(0) => {
                            // stdin EOF — half-close by sending a Close and break.
                            let _ = self.sink.send(WsMessage::Close(None)).await;
                            break;
                        }
                        Ok(n) => {
                            if self.sink.send(WsMessage::Binary(buf[..n].to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Read from the WebSocket — write binary frames to stdout, ignore others.
                msg = self.source.next() => {
                    match msg {
                        Some(Ok(WsMessage::Binary(data))) => {
                            if stdout.write_all(&data).await.is_err() {
                                break;
                            }
                            let _ = stdout.flush().await;
                        }
                        Some(Ok(WsMessage::Text(s))) => {
                            // Server-side errors arrive as text frames (rare). Print to stderr.
                            let _ = stdout.flush().await;
                            eprintln!("[pty server] {s}");
                        }
                        Some(Ok(WsMessage::Ping(_))) | Some(Ok(WsMessage::Pong(_))) => continue,
                        Some(Ok(WsMessage::Frame(_))) => continue,
                        Some(Ok(WsMessage::Close(_))) | None => break,
                        Some(Err(e)) => return Err(anyhow!("PTY WS read error: {e}")),
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{build_pty_ws_url, normalize_remote_url, url_encode};

    #[test]
    fn normalize_bare_host_port() {
        assert_eq!(
            normalize_remote_url("127.0.0.1:8443"),
            "ws://127.0.0.1:8443/ipc"
        );
    }

    #[test]
    fn normalize_keeps_explicit_scheme() {
        assert_eq!(normalize_remote_url("ws://host:1/ipc"), "ws://host:1/ipc");
        assert_eq!(normalize_remote_url("wss://host/ipc"), "wss://host/ipc");
    }

    #[test]
    fn normalize_appends_ipc_when_missing() {
        assert_eq!(normalize_remote_url("ws://host:1"), "ws://host:1/ipc");
    }

    // ---- Phase 12: PTY WS URL builder + token encoder ----

    #[test]
    fn pty_ws_url_uses_bare_host_port_shortcut() {
        let url = build_pty_ws_url("127.0.0.1:8443", "pty-deadbeef", "tk");
        assert_eq!(url, "ws://127.0.0.1:8443/pty/pty-deadbeef?token=tk");
    }

    #[test]
    fn pty_ws_url_strips_existing_ipc_path() {
        let url = build_pty_ws_url("ws://host:1/ipc", "pty-1234", "tk");
        assert_eq!(url, "ws://host:1/pty/pty-1234?token=tk");
    }

    #[test]
    fn pty_ws_url_preserves_wss_for_tls() {
        let url = build_pty_ws_url("wss://host/ipc", "pty-aa", "tk");
        assert_eq!(url, "wss://host/pty/pty-aa?token=tk");
    }

    #[test]
    fn pty_ws_url_percent_encodes_token() {
        let url = build_pty_ws_url("127.0.0.1:8443", "pty-1", "a b/c?d");
        assert_eq!(url, "ws://127.0.0.1:8443/pty/pty-1?token=a%20b%2Fc%3Fd");
    }

    #[test]
    fn url_encode_leaves_unreserved_chars_alone() {
        assert_eq!(url_encode("aZ09-_.~"), "aZ09-_.~");
    }

    #[test]
    fn url_encode_encodes_reserved_chars() {
        assert_eq!(url_encode(" "), "%20");
        assert_eq!(url_encode("/"), "%2F");
        assert_eq!(url_encode("&="), "%26%3D");
    }

    // ---- Phase 14: Sec-WebSocket-Protocol Bearer.<token> request builder ----

    #[test]
    fn build_ws_client_request_emits_dotted_bearer_subprotocol() {
        use super::build_ws_client_request;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let builder =
            build_ws_client_request("ws://127.0.0.1:8443/ipc", "hunter2").expect("builds");
        let req = builder.into_client_request().expect("into request");
        let proto_value = req
            .headers()
            .get("sec-websocket-protocol")
            .expect("subprotocol header set")
            .to_str()
            .expect("ascii header value");
        assert!(
            proto_value.contains("Bearer.hunter2"),
            "expected Bearer.hunter2 subprotocol, got {proto_value:?}"
        );
    }

    #[test]
    fn build_ws_client_request_rejects_invalid_url() {
        use super::build_ws_client_request;
        let err = build_ws_client_request("not a url", "tk").unwrap_err();
        let s = format!("{err:#}");
        assert!(s.contains("WebSocket URL"), "got: {s}");
    }

    #[test]
    fn build_ws_client_request_keeps_url_unchanged() {
        use super::build_ws_client_request;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let builder = build_ws_client_request("wss://example.test/ipc", "abc").expect("builds");
        let req = builder.into_client_request().expect("into request");
        assert_eq!(req.uri().to_string(), "wss://example.test/ipc");
    }
}
