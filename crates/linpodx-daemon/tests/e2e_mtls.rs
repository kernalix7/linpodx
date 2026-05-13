//! End-to-end: spawn the daemon with --remote-listen + TLS + mTLS, generate a
//! self-signed CA + server + client cert pair via `rcgen`, then run a CLI
//! `version` over `wss://` and assert the round-trip succeeds.
//!
//! `#[ignore]` because it transitively needs the daemon binary (which needs
//! Podman to start). Run with `cargo test -p linpodx-daemon --test e2e_mtls -- --ignored --test-threads=1`.

use assert_cmd::Command as AssertCommand;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct DaemonGuard {
    child: std::process::Child,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_socket(socket: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if socket.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    port
}

/// Generate a CA + leaf cert signed by the CA, both written as PEM files.
/// Returns (ca_pem_path, leaf_cert_pem_path, leaf_key_pem_path).
fn write_ca_and_leaf(
    dir: &Path,
    leaf_cn: &str,
    san: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    // CA
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-test-ca");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self_signed");
    let ca_pem_path = dir.join("ca.pem");
    std::fs::write(&ca_pem_path, ca_cert.pem()).unwrap();

    // Leaf signed by CA
    let mut leaf_params = CertificateParams::new(vec![san.to_string()]).expect("leaf params");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, leaf_cn);
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf signed_by ca");
    let leaf_cert_path = dir.join(format!("{leaf_cn}.crt"));
    let leaf_key_path = dir.join(format!("{leaf_cn}.key"));
    std::fs::write(&leaf_cert_path, leaf_cert.pem()).unwrap();
    std::fs::write(&leaf_key_path, leaf_key.serialize_pem()).unwrap();

    (ca_pem_path, leaf_cert_path, leaf_key_path)
}

#[test]
#[ignore]
fn mtls_version_call_roundtrips() {
    let workdir = tempfile::tempdir().expect("tempdir");
    let certdir = workdir.path().join("certs");
    std::fs::create_dir_all(&certdir).unwrap();

    // Single CA signs both server and client leaf certs.
    let (ca_pem, server_cert, server_key) =
        write_ca_and_leaf(&certdir, "linpodx-server", "localhost");
    let (_ca2, client_cert, client_key) =
        write_ca_and_leaf(&certdir, "linpodx-client", "linpodx-client");
    // Re-use the first CA for client trust by overwriting client_ca with the
    // first ca.pem so both leafs verify against the same root.
    let client_ca = ca_pem.clone();

    // Sign client cert with the SAME ca that signed server cert. Re-do client cert
    // generation manually here to share the same CA key. Easiest: regenerate with
    // a helper that takes existing CA in scope. Simpler: just sign both leafs with
    // the same CA right here.
    // (The helper above generates a new CA each call, which is wrong for mTLS.
    // Replace with an inline pair.)
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-test-ca-shared");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("shared ca");
    std::fs::write(&ca_pem, ca_cert.pem()).unwrap();

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("server params");
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-server");
    let server_kp = KeyPair::generate().expect("server kp");
    let server_signed = server_params
        .signed_by(&server_kp, &ca_cert, &ca_key)
        .expect("server signed");
    std::fs::write(&server_cert, server_signed.pem()).unwrap();
    std::fs::write(&server_key, server_kp.serialize_pem()).unwrap();

    let mut client_params =
        CertificateParams::new(vec!["linpodx-client".to_string()]).expect("client params");
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-client");
    let client_kp = KeyPair::generate().expect("client kp");
    let client_signed = client_params
        .signed_by(&client_kp, &ca_cert, &ca_key)
        .expect("client signed");
    std::fs::write(&client_cert, client_signed.pem()).unwrap();
    std::fs::write(&client_key, client_kp.serialize_pem()).unwrap();

    let socket = workdir.path().join("linpodx.sock");
    let db = workdir.path().join("state.db");
    let pod_root = workdir.path().join("podman-root");
    let pod_runroot = workdir.path().join("podman-runroot");
    let port = pick_free_port();
    let listen = format!("127.0.0.1:{port}");

    let bin = AssertCommand::cargo_bin("linpodx-daemon")
        .expect("locate linpodx-daemon")
        .get_program()
        .to_owned();
    let child = Command::new(&bin)
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .arg("--podman-root")
        .arg(&pod_root)
        .arg("--podman-runroot")
        .arg(&pod_runroot)
        .arg("--remote-listen")
        .arg(&listen)
        .arg("--remote-token")
        .arg("hunter2")
        .arg("--remote-cert")
        .arg(&server_cert)
        .arg("--remote-key")
        .arg(&server_key)
        .arg("--client-ca")
        .arg(&client_ca)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = DaemonGuard { child };

    assert!(
        wait_for_socket(&socket, Duration::from_secs(20)),
        "daemon never created Unix socket"
    );
    std::thread::sleep(Duration::from_millis(500));

    let url = format!("wss://{listen}/ipc");
    let mut cmd = AssertCommand::cargo_bin("linpodx").expect("locate cli");
    cmd.arg("--remote")
        .arg(&url)
        .arg("--token")
        .arg("hunter2")
        .arg("--ca")
        .arg(&ca_pem)
        .arg("--client-cert")
        .arg(&client_cert)
        .arg("--client-key")
        .arg(&client_key)
        .arg("version");
    let out = cmd.output().expect("run cli");
    assert!(
        out.status.success(),
        "cli mTLS round-trip failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[ignore]
fn mtls_rejects_client_without_cert() {
    let workdir = tempfile::tempdir().expect("tempdir");
    let certdir = workdir.path().join("certs");
    std::fs::create_dir_all(&certdir).unwrap();

    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-test-ca");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca");

    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "linpodx-server");
    let server_kp = KeyPair::generate().expect("server kp");
    let server_signed = server_params
        .signed_by(&server_kp, &ca_cert, &ca_key)
        .expect("server signed");

    let ca_pem = certdir.join("ca.pem");
    let server_cert = certdir.join("server.crt");
    let server_key = certdir.join("server.key");
    std::fs::write(&ca_pem, ca_cert.pem()).unwrap();
    std::fs::write(&server_cert, server_signed.pem()).unwrap();
    std::fs::write(&server_key, server_kp.serialize_pem()).unwrap();

    let socket = workdir.path().join("linpodx.sock");
    let db = workdir.path().join("state.db");
    let pod_root = workdir.path().join("podman-root");
    let pod_runroot = workdir.path().join("podman-runroot");
    let port = pick_free_port();
    let listen = format!("127.0.0.1:{port}");

    let bin = AssertCommand::cargo_bin("linpodx-daemon")
        .expect("locate linpodx-daemon")
        .get_program()
        .to_owned();
    let child = Command::new(&bin)
        .arg("--socket")
        .arg(&socket)
        .arg("--db")
        .arg(&db)
        .arg("--podman-root")
        .arg(&pod_root)
        .arg("--podman-runroot")
        .arg(&pod_runroot)
        .arg("--remote-listen")
        .arg(&listen)
        .arg("--remote-token")
        .arg("hunter2")
        .arg("--remote-cert")
        .arg(&server_cert)
        .arg("--remote-key")
        .arg(&server_key)
        .arg("--client-ca")
        .arg(&ca_pem)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");
    let _guard = DaemonGuard { child };

    assert!(
        wait_for_socket(&socket, Duration::from_secs(20)),
        "daemon never created Unix socket"
    );
    std::thread::sleep(Duration::from_millis(500));

    // Client connects WITHOUT --client-cert/--client-key — handshake must fail.
    let url = format!("wss://{listen}/ipc");
    let mut cmd = AssertCommand::cargo_bin("linpodx").expect("locate cli");
    cmd.arg("--remote")
        .arg(&url)
        .arg("--token")
        .arg("hunter2")
        .arg("--ca")
        .arg(&ca_pem)
        .arg("version");
    let out = cmd.output().expect("run cli");
    assert!(
        !out.status.success(),
        "cli unexpectedly succeeded without client cert"
    );
}
