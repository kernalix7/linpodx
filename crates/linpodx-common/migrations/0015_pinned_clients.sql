-- Phase 15 Stream C: pinned WebSocket client certificates.
--
-- When the daemon is started with `--pin-clients`, every TLS handshake whose
-- peer presents a client certificate is matched against this table by SHA-256
-- fingerprint of the leaf certificate's DER. A match accepts the upgrade and
-- emits an `AuditSinkKind::WsClientCertPinned` audit row; a miss rejects with
-- HTTP 403 and an `AuditSinkKind::RemoteAuthFailed` row.
--
-- The fingerprint is the lowercase hex of `Sha256(cert_der)` — the same digest
-- displayed by `openssl x509 -fingerprint -sha256 -noout` after stripping the
-- separator colons. The label is operator-supplied free-form text used only
-- for the audit payload and the `pin-client list` output.

CREATE TABLE IF NOT EXISTS pinned_clients (
    fingerprint TEXT PRIMARY KEY,
    label       TEXT NOT NULL DEFAULT '',
    enrolled_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_pinned_clients_label ON pinned_clients(label);
