# Changelog

**English** | [한국어](docs/CHANGELOG.ko.md)

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!--
Template for each new version section. Keep `### Highlights` first: the release
workflow extracts the whole section for the GitHub Release body.

### Highlights

**One-sentence headline.** Optional 1-2 sentence elaboration if useful.

- Most important user-visible change
- Second most important change
- Third important change

### Added
### Changed
### Fixed
-->

## [0.1.1] - 2026-05-14

### Highlights

**Security-fix patch.** Closes 14 advisories against `wasmtime` (incl. CRITICAL
sandbox-escape RUSTSEC-2026-0095 / -0096), the `hickory-proto` baseline DoS
RUSTSEC-2026-0119, `time` stack-exhaustion RUSTSEC-2026-0009, and the `serde_yml`
unsoundness RUSTSEC-2025-0068 / -0067. No public API changes.

- `wasmtime 26.0.1 → 43.0.2` — drop the WebAssembly plugin sandbox onto a CVE-free
  release line. The 24 LTS branch lacks backports for 6 Winch / pooling-allocator
  advisories; 43.x is API-compatible with linpodx-plugin and required zero source
  changes downstream.
- `hickory-{resolver,server,proto} 0.24 → 0.25` — closes the message-encoding CPU
  exhaustion in the egress DNS filter. Adapted `linpodx-netfilter::resolver` and
  `linpodx-runtime::network_filter` for the new `TokioResolver` builder API.
- `serde_yml → serde_norway` — `serde_yml` was archived upstream (RUSTSEC-2025-0068)
  and pulled the unsound `libyml` (RUSTSEC-2025-0067). `serde_norway` is the
  maintained drop-in fork of `serde_yaml`; touches workspace dep + 4 crate manifests
  + 6 source files (cli/main.rs, sandbox/{profile,schema,snapshot_trigger}.rs,
  cluster/k8s.rs).
- `time 0.3.45 → 0.3.47` — transitive bump via `cargo update -p time` closes the
  stack-exhaustion DoS in x509-parser / rcgen.

### Changed

- `.cargo/audit.toml` (new) mirrors `deny.toml [advisories].ignore` so
  `rustsec/audit-check` exits 0 on CI. Nine well-rationalized waivers cover
  hickory NSEC3 (we never validate DNSSEC), the hickory encoder DoS (loopback-only
  forwarder), the rsa Marvin advisory (sqlx-mysql is in `Cargo.lock` only, not in
  the compiled graph — workspace `sqlx` uses `default-features = false` with only
  `runtime-tokio,sqlite,macros,migrate`), and the transitive unmaintained crates
  (`backoff`, `instant`, `paste`, `rustls-pemfile`, `serial`, `lru` GUI-only).
- `deny.toml` adds `BSL-1.0` and `CDLA-Permissive-2.0` to the license allow-list
  (Boost-licensed `ryu` / `clipboard-win` / `error-code` / `xxhash-rust` and the
  Mozilla CA-trust-store data crate `webpki-roots`), removes the now-unused
  `Unicode-DFS-2016`, and pins `jsonpath-rust` to MIT via `[[licenses.clarify]]`
  (LICENSE file ships MIT; upstream Cargo.toml omits the `license =` field).

### Fixed

- 14 `wasmtime` advisories closed in full via the 43.x bump, including the two
  CRITICAL sandbox-escape paths that initially demoted v0.1.0 to prerelease.

## [0.1.0] - 2026-05-13

### Highlights

**First pre-alpha release of linpodx.** This release establishes the Linux-native
container manager, AI-agent sandbox, desktop GUI, remote daemon, plugin system, and
multi-distro foundation that future `0.x` releases will harden.

- Local daemon + Rust CLI + iced GUI over a shared JSON-RPC surface.
- AI-agent sandbox with approvals, tamper-evident audit log, sessions, snapshots, and bridge controls.
- GUI passthrough, multi-distro templates, remote daemon security, plugin signing, and cluster scaffolding.
- Source installer/uninstaller, release artifacts, and a winpodx-style release workflow.

### Added — Core

- Rust workspace with daemon, CLI, GUI, runtime, sandbox, common IPC, distro, MCP, network filtering, plugin, cluster, and web UI crates.
- Rootless Podman-backed container lifecycle: list, inspect, create, start, stop, remove, pull, logs, exec, and minimum Podman version detection.
- Unix-socket JSON-RPC daemon with typed IPC envelopes, event notifications, graceful shutdown, structured logging, SQLite migrations, and stable error responses.
- CLI coverage for containers, images, volumes, networks, snapshots, sessions, MCP bridges, distro environments, passthrough, egress policy, remote daemon access, cluster operations, plugins, K8s operations, and registry workflows.
- Image, volume, and network management, port mapping, registry push with optional client certificates, multi-arch manifest creation and push, and progress/event streaming.
- Snapshot lifecycle with async jobs, lineage, diff support, branch aliases, pruning, encryption status, and file-level `diff_v2` over OCI layers.
- Session timelines that merge audit and MCP activity by container, plus table and JSON output across the CLI.
- Source-based `install.sh` and `uninstall.sh` for release/main/local checkout installs, GUI launcher setup, optional helper capability setup, and data-preserving uninstall.

### Added — AI sandbox

- YAML sandbox profiles with network policy, mount whitelist, capability drop/add, CPU and memory caps, read-only rootfs, distro/systemd metadata, passthrough policy, and approval gates.
- Policy engine that enforces denied mounts, denied capabilities, network-disabled profiles, read-only rootfs, resource caps, and profile reloads before container creation.
- Tamper-evident audit log with SHA-256 hash chaining, verification command, typed audit events, and event publication.
- Approval workflow for sensitive operations with request fan-out, timeouts, grant/deny outcomes, CLI listener, and GUI subscription support.
- MCP host-stdio bridge with allowlists, per-method policy, audit events, lifecycle commands, and session integration.
- Agent-oriented safety features including pre-run snapshots, rollback support, network allowlists, and isolated runtime configuration.

### Added — Multi-distro

- Distro templates for Ubuntu, Fedora, Arch, Debian, Alpine, and NixOS with default image, init mode, package list, shell, and recommended passthrough.
- VM-mode lightweight environments with persistent home volumes, auto-restart behavior, `systemd` support, and `--userns=keep-id` host UID/GID mapping.
- Distro CLI and IPC for listing, inspecting, creating, building, entering, and removing managed environments.

### Added — GUI

- iced desktop dashboard with live event subscriptions, reconnect handling, and container/image/volume/network views.
- Embedded web UI with REST endpoints, legacy fallback, Leptos SPA support, sortable/filterable views, per-row modals, logs view, image push flow, and exec workflows.
- Interactive PTY support over WebSocket with CLI raw-mode handling and browser terminal integration.
- GUI/container passthrough support for Wayland, X11, audio, GPU, DBus session bus, clipboard, HiDPI/theme environment, and optional desktop file registration.

### Added — Cluster

- P2P gossip, node liveness transitions, and container view aggregation over the remote transport.
- Kubernetes read/write adapter for pod, service, namespace, and deployment operations with daemon IPC and CLI commands.
- Raft-backed leader election, multi-node membership, learner promotion, voter demotion, HTTP Raft transport, and audit events.
- Replicated cluster state machine for container proposals/removals, state snapshots, install-snapshot restore, and raft-first/fallback container views.

### Added — Plugins

- WASM plugin runtime with approval short-circuiting, audit filters, profile validation, network decisions, runtime injection, and example plugins.
- Plugin manifest installation path with signed package support, detached signatures, publisher key lookup, unsigned-plugin bypass gate, and audit events.
- ed25519 signature verification with strict signature checks, key registry search paths, key listing, revocation markers, and revoke/list CLI commands.

### Added — Remote

- WebSocket remote daemon transport with bearer authentication, browser-friendly query-token fallback, first-frame fallback, and subprotocol bearer support.
- mTLS remote daemon mode, certificate generation command, server/client certificate loading, and client common-name extraction.
- Client certificate pinning with SQLite persistence, add/list/remove commands, audit events, and TOFU auto-enrollment with count and time-window controls.

### Security

- Seccomp OCI JSON and AppArmor profile compilation, SELinux dynamic and static label flows, runtime fallback option, and security option propagation into Podman.
- L4 egress firewall helper with nftables enforcement and DNS-based egress allowlist support.
- Snapshot at-rest encryption using AES-256-GCM, passphrase/raw-key sources, ciphertext hashing, side-car metadata, and decrypt/load path.
- Supply-chain controls for plugin signing, key revocation, cargo audit, cargo deny, license policy, and exact pinning for selected crypto dependencies.
- Remote hardening with mTLS, bearer token handling, client certificate pinning, TOFU expiry, and detailed audit events for accepted/rejected paths.

### Performance

- Live container metrics via `podman stats` with GUI sparkline support.
- Criterion benchmark tooling, per-platform benchmark baselines, Linux x86_64 and Linux ARM64 CI coverage, and comparison scripts for regression checks.
- Async snapshot jobs and streaming operations keep long-running runtime work off the interactive control path.

### Changed

- MSRV: 1.85 (was 1.83).
- CI tests the stable toolchain and Rust 1.85 baseline.
- Release notes are organized by user-visible capability area, with phase-level development notes kept below as pre-release history.

### Documentation

- README, install guide, release process, contribution guide, security policy, code of conduct, architecture notes, ADRs, scenarios, example profiles, and Korean documentation coverage.
- README reorganized around quick install, launch, feature matrix, workflows, architecture, supported distros, and testing.
- Example sandbox profiles for GUI passthrough, distro environments, strict MCP policy, interactive mount approvals, and signed/unsigned plugin workflows.

### Testing

- `cargo test --workspace`: 829 passed / 0 failed / 54 ignored.
- 883 total tracked tests including ignored live integration coverage.
- Pre-release integration coverage spans container, image, volume, network, approval, event, sandbox, snapshot, session, MCP, distro, passthrough, egress, K8s, cluster, remote, plugin, and encryption flows.

## Pre-release history (Phase 0..17)

### Added — Phase 16 (Cluster State Replication + Snapshot Encryption + Supply-Chain Polish)

- **Cluster state replication via Raft state machine** (`linpodx-cluster::election`) — Phase 14/15 의 leader-elect + multi-node membership 위에 진짜 application log + state machine 활성. `AppData` enum 3-variant (`Noop` / `ProposeContainer{node_id, container: ContainerSummary}` / `RemoveContainer{node_id, container_id}`). MemStore.containers `BTreeMap<(node_id, container_id), ContainerSummary>` + `apply_to_state_machine` 진짜 구현 (Phase 15 까지 빈 placeholder). SnapshotPayload 에 container map 포함, `install_snapshot` 복원. RaftNode helpers: `state_snapshot()` / `propose_container()` / `propose_container_remove()` / `is_leader()`. `ClusterContainerView` IPC 가 raft.last_applied>0 + non-empty 시 raft 우선, 아니면 기존 gossip aggregate 폴백 (backward compat). 신규 IPC: `ClusterStateGet` / `ClusterStateProposeContainer`. CLI: `linpodx cluster state {get, propose --node-id <n> --container-id <c> [--image <i>]}`. Audit: `ClusterStateApplied` / `ClusterStateProposeFailed`.
- **Snapshot at-rest encryption (AES-256-GCM)** — 신규 `linpodx-runtime/src/snapshot_crypto.rs` (414L): Aes256Gcm round-trip, sha2 1000-round salted KDF, base64 raw-key path, OsRng nonce, `EncryptionConfig` + `KeySource` (Env/Passphrase/Explicit). 활성 조건: `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` 또는 `LINPODX_SNAPSHOT_KEY` env 둘 중 하나 set (둘 다 unset 면 미암호화 — backward compat). `SnapshotBackend` trait 에 `encryption_config(&self) -> Option<&EncryptionConfig>` (default None). PodmanCommitBackend 는 unit struct 유지 (sandbox API 호환) + 프로세스 전역 `active_encryption_config()` `OnceLock` cache. side-car 파이프라인: `encrypt_committed_image` (podman save → AEAD → atomic blob.enc + meta.json), `decrypt_and_load` (verify ciphertext sha256 → AEAD decrypt → podman load). 신규 migration `0016_snapshot_encryption.sql`: snapshots 테이블 encrypted/algorithm/key_source/ciphertext_sha256 컬럼 + idx_snapshots_encrypted index. 신규 IPC: `SnapshotEncryptionStatus` (DB row + 디스크 side-car truth + 404 폴백). CLI: `linpodx snapshot encryption-status <id>`. Audit: `SnapshotEncrypted` / `SnapshotDecryptFailed`.
- **Plugin key revocation/rotation** (`linpodx-plugin::key_registry`) — `KeyRegistryError::Revoked` variant + `KeyRegistry::revoke(publisher, reason)` (`<publisher>.revoked` JSON marker idempotent) + `lookup()` 가 marker 인식 → Revoked + `list_keys() -> Vec<KeyEntry>` (publisher + sha256 fingerprint + active/revoked + revoked_at + reason). 신규 IPC: `PluginKeyList` / `PluginKeyRevoke`. CLI: `linpodx plugin key {list, revoke <publisher> --reason <r>}`. Audit: `PluginKeyRevoked`. plugin_store install path 변경 0 — `KeyRegistryError::Revoked` 가 Display 통해 "publisher 'X' key has been revoked: Y" 형태로 자동 surface.
- **Pin TOFU auto-enroll** (`linpodx-daemon::pin_store`) — `TofuMode { enabled, max_enrollments, current_count }` + `should_enroll()` + `record_enrollment()` (saturating). `TofuHandle = Arc<Mutex<TofuMode>>` Dispatcher / RemoteState 공유. `ws_handler` 의 pin check: mismatch + `should_enroll()` 시 `pin_store.insert(fp, "tofu-auto")` + accept upgrade. cap 도달 시 latch off → 기존 403 path. 신규 IPC: `DaemonPinClientTofuEnable` (--disable 시 counter reset). CLI: `linpodx daemon pin-client tofu {--enable [--max <N>], --disable}`. Audit: `WsClientCertTofuEnrolled`.
- **bench CI multi-platform** — `.github/workflows/bench.yml` matrix.include 에 `platform: linux-aarch64, runner: ubuntu-24.04-arm` (GitHub-hosted ARM64 runner) 추가. bench-results/linux-aarch64.json 베이스라인 부재 시 soft-fail.
- **Workspace deps**: `aes-gcm = { version = "0.10", default-features = false, features = ["aes", "alloc", "rand_core"] }` + `rand = { version = "0.8", default-features = false, features = ["std", "std_rng"] }`.
- 710 unit tests total (Phase 15 660 → +50 lib / 50 ignored 변동 없음).

### Added — Phase 15 (Cluster Multi-Node + Plugin Signing + Polish)

- **Cluster Raft multi-node activation** (`linpodx-cluster::election`) — Phase 14 의 prepped RaftHttpFactory 활성. `start_with_network<F: RaftNetworkFactory>` 신규 (NoopNetworkFactory 자리에 RaftHttpFactory 주입). `add_learner_with_audit` / `promote_with_audit` / `remove_node` voter→demote audit. `membership_snapshot() -> MembershipSnapshot { voters, learners, current_term }`. addr_map / label_map 동기 mirror. 신규 `gossip::raft_membership_sync_round` + `run_raft_sync_loop` (5s 주기 promote_after 5s). main.rs 가 `--cluster-raft-advertise` 있으면 `start_with_network(RaftHttpFactory::new())` + 다중 노드일 때 sync loop spawn. 신규 IPC: `ClusterRaftStatus` / `ClusterRaftPromote`. CLI: `linpodx cluster {status, promote <node_id>}`. Audit: `ClusterRaftPromoted` / `ClusterRaftDemoted`.
- **Plugin ed25519 signature verification** (`linpodx-plugin`) — 신규 `signing.rs`: `verify_plugin_signature(wasm, sig_b64, pub_pem)` ed25519-dalek 2 `VerifyingKey::from_public_key_pem` + `verify_strict` (malleable sig 거부). 신규 `key_registry.rs`: `KeyRegistry` 가 `LINPODX_PLUGIN_KEYS_DIR` > `$XDG_CONFIG_HOME/linpodx/plugin-keys/` > `$HOME/.config/linpodx/plugin-keys/` > `/etc/linpodx/plugin-keys/` 순서 검색. ASCII-stem sanitiser. PluginManifest 에 `publisher` + `signature_b64` optional. plugin_store install path: params override > detached `signature.b64` > `manifest.signature_b64` 우선순위 + params override > registry by publisher. 검증 성공 → `PluginSignatureVerified` audit + install. 검증 실패 → `PluginSignatureRejected` + ABORT. 미서명 + `LINPODX_ALLOW_UNSIGNED_PLUGINS in {1,true,yes}` → audit accepted=true bypass. CLI `linpodx plugin install --signature <p> --public-key <p>`. examples/plugins/signed-noop/ (NEW): manifest + 8-byte noop wasm + signature.b64 + test.pub PEM + test.key.b64 + README.
- **WS client cert pinning** (`linpodx-daemon`) — `--pin-clients` daemon flag (mTLS 전제). 신규 `pin_store.rs`: `PinnedClientStore` (sha256 leaf DER → 64-char lowercase hex, PEM 재인코딩 안정). 신규 migration `0015_pinned_clients.sql`. 신규 IPC: `DaemonPinClient{Add, List, Remove}`. ws_handler 가 `mtls_peers` 에서 fingerprint peek → `pin_store.contains()` → match 시 `WsClientCertPinned` audit + accept, miss 시 HTTP 403. CLI: `linpodx daemon pin-client {add <cert.pem> --label X, list, remove <fp>}`.
- **SELinux runtime fallback** — `LINPODX_SELINUX_RUNTIME_FALLBACK=1` env 시 `secprofile.rs::compile()` 가 동적 .te 컴파일 실패 시 `selinux_static_label = Some("container_t")` substitute + `SelinuxLabelRuntimeFallback` audit. env 없음 = 기존대로 hard error. literal "1" 만 활성.
- **bench CI per-platform baseline** — `.github/workflows/bench.yml` matrix-strategy `platform`-keyed (linux-x86_64), push-to-main 트리거, sticky PR comment per platform.
- 660 unit tests total (Phase 14 618 → +42 lib / +1 ignored).

### Added — Phase 14 (Security-Finalize + WebUI Vendor + Push mTLS + Cluster Raft)

- **EgressEnforcer plugin Deny actual enforce** (`linpodx-runtime::egress_enforcer`) — Phase 13 audit-only chain 결과를 helper allowlist 에서 REMOVE (default `policy drop` take over). `EgressDenyEnforced` audit.
- **SELinux 정적 라벨 흐름** — `CompiledProfile.selinux_static_label: Option<String>` 추가. `compile_selinux()` 가 `schema.selinux_label.is_some()` 시 동적 .te 파이프라인 SHORT-CIRCUIT. `to_security_opts()` 우선순위 = static > dynamic. `profile::validate` 가 mutual-exclusion 검증. `dedup_label_type_first_wins` defence-in-depth. `SelinuxStaticLabelApplied` audit.
- **WS Sec-WebSocket-Protocol 토큰** — `parse_bearer_subprotocol(&HeaderMap)` 가 `Bearer.<token>` (RFC 6455 dot-form) 와 `Bearer <token>` 모두 수용. `ws_handler` + `pty_ws_handler` 가 헤더 우선 → query string 폴백 → first-frame envelope 폴백. echo response header. CLI 도 헤더 우선. `WsAuthSubprotocol` audit.
- **xterm.js vendoring** — `LINPODX_VENDOR_XTERM=1` 빌드 토글. `linpodx-webui/build.rs` (NEW) 가 ureq 2 로 jsDelivr 에서 다운로드 → OUT_DIR. daemon `/assets/xterm.{js,css}` `/assets/addon-fit.js` 라우트. `serve_root()` OnceLock 캐시 rewrite.
- **image push mTLS to private registry** — `podman.rs::push()` 가 `cert_dir: Option<&Path>` → `--cert-dir <p>` argv. CLI `linpodx image push --cert-dir <p>`. `ImagePushTls` audit.
- **Cluster Raft single-node leader-elect** (`linpodx-cluster::election`) — openraft 0.9.24 통합. `LinpodxRaft` `RaftTypeConfig` (NodeId=u64, BasicNode), `MemStore` (RaftStorage v1 → `openraft::storage::Adaptor` → v2), `LeaderState` (Leader/Follower/Candidate/Learner/Unknown), `RaftNode` facade, `node_id_from_string()`, `VoteSink` trait + `NoopVoteSink` + `SqliteVoteSink`. background metric_pump 로 `ClusterLeaderElected` / `ClusterLeaderLost` audit. 신규 `raft_http.rs` (`raft_router(node) -> axum::Router` POST `/append /vote /snapshot` + `RaftHttpFactory` + `RaftHttpClient` over reqwest). `daemon::Dispatcher.with_raft` builder. main.rs `--cluster-raft` flag. 신규 IPC: `ClusterLeaderGet` / `ClusterRoleGet`. CLI: `linpodx cluster {leader, role}`. 신규 migration `0014_raft_state.sql`.
- **Workspace deps**: `ed25519-dalek = { version = "2", default-features = false, features = ["std", "pkcs8", "pem"] }` (Phase 15 도입) + `openraft = "0.9"` (cluster crate per-crate) + `aes-gcm` 등 Phase 16. workspace `[workspace.dependencies]` 에 추가.
- 618 unit tests total (Phase 13 545 → +73).

### Added — Phase 13 (K8s Write-Side + xterm.js Web UI + Plugin v3 Extensions)

- **K8s write-side** (`linpodx-cluster::k8s`) — `K8sAdapter` +4 메서드 (`create_pod` / `delete_pod` / `create_namespace` / `scale_deployment` via kube::Api + JSON merge patch). 신규 IPC: `K8sPodCreate` / `K8sPodDelete` / `K8sNamespaceCreate` / `K8sDeploymentScale`. CLI: `linpodx k8s {pod create <yaml|->, pod delete <name>, ns create <name>, scale <deployment> --replicas <N>}`. Audit: `K8sPodCreated` / `K8sPodDeleted` / `K8sNamespaceCreated` / `K8sDeploymentScaled`.
- **xterm.js Web UI 통합** (`linpodx-webui`) — index.html 에 @xterm/xterm@5 + @xterm/addon-fit@0.10 jsDelivr CDN. 신규 `xterm.rs` (196L) safe Rust wrapper via js_sys::Reflect. LogsModal plain text → xterm-container `<div>` + `EventKind::Log` 라인 → `term.write_str`. 신규 ExecPtyModal (350L): WebSocket binary (binaryType="arraybuffer") + xterm 양방향. PtySocket Drop 시 deterministic ws.close (PTY leak 방지).
- **Plugin SDK extra extension points** (`linpodx-plugin`) — `network_trace` extension + `runtime_injector` extension. `NetworkDecision` enum (Allow/Deny/AuditOnly, precedence Deny>AuditOnly>Allow). InjectorPayload concat-merge. wasm exports `evaluate_network_trace` / `evaluate_runtime_injector`. ContainerCreate dispatch arm 가 `evaluate_runtime_injector` 호출 후 `opts.env/command/security_opts` merge. 샘플 플러그인 2: `examples/plugins/audit-egress/` (network_trace AuditOnly + host_log) + `inject-tracing-env/` (runtime_injector OTEL_* env). Audit: `PluginNetworkTraceCalled` / `PluginRuntimeInjectorCalled`.
- 545 unit tests total (Phase 12 515 → +30).

### Added — Phase 12 (SELinux + Web UI Modals + Interactive PTY)

- **SELinux .te synthesis** (`linpodx-sandbox::secprofile`) — 동적 .te 생성 + `checkmodule + semodule_package + semodule -i`. `--security-opt label=type:<type>` security_opts 주입. graceful fallback (LINPODX_TEST_SELINUX override). Audit: `SelinuxCompiled` / `SelinuxApplied`. **Goal #5 Security-first 100% 도달.**
- **Web UI per-row modals** (`linpodx-webui`) — `ListTable` children-slot refactor + 3 신규 modal (exec / logs / push) wired into 4 view call-sites. helpers.rs.
- **Interactive PTY proxy** (`linpodx-runtime::podman` + `linpodx-daemon::remote`) — portable-pty 0.8 master/slave on the daemon + axum `/pty/<bridge_id>` WebSocket binary (query-string token). CLI `linpodx exec -i -t` over crossterm raw mode + `RawModeGuard` panic-safe. PtyRegistry single-use bridge_id (race-condition safe).
- 515 unit tests total.

### Added — Phase 11 (Secprofile Compiler + Container Streaming + Image Push)

- **Secprofile compiler** (`linpodx-sandbox::secprofile`) — seccomp OCI JSON via seccompiler 0.5 + AppArmor text via `apparmor_parser -r`. `linpodx sandbox profile compile` CLI. Audit: `SeccompCompiled` / `ApparmorCompiled` / `SeccompApplied` / `ApparmorApplied`.
- **Container exec / log streaming / image pull progress** — 신규 `EventKind::Log`, GUI Exec/Logs modals + 1000-line ring. CLI `linpodx exec` / `linpodx logs -f` / `linpodx image pull` (progress events). Audit: `ContainerExecCalled` / `ContainerLogsStreamed` / `ImagePullStarted`.
- **Image registry push + multi-arch manifest** — `podman push` (with `--creds`), `podman manifest create / add / push`. 신규 IPC: `ImagePush` / `ImageManifestCreate` / `ImageManifestPush`. CLI: `linpodx image {push, manifest {create, push}}`. Audit: `ImagePushed` / `ImageManifestCreated`.
- 485 unit tests total.

### Added — Phase 10 (Polish + Diff_v2 file-changes + K8s read-only)

- **Polish 5 sub-tasks**: `CreateOptions.rootfs` 주입 (Phase 9 audit-only finish via overlayfs mount registry lookup), WS `?token=<t>` query-string (browser auth), `linpodx daemon cert generate` rcgen-based (CA + server SAN + client leaf), Web UI v2 (cards + sort + filter + dark gradient via leptos `view!` — XSS safe), bench CI workflow + bench-tools/compare.py.
- **diff_v2 file-level diff** — 신규 `linpodx-runtime/src/oci_tar.rs` (322L). `podman save -o` + manifest.json walk + layer .tar.gz auto-detect + .wh.* whiteout marker skip + topmost-layer-metadata-wins. snapshot.rs::diff_v2 → `SnapshotDiffV2Response.file_changes` populated.
- **K8s read-only adapter** (`linpodx-cluster::k8s`, NEW 226L) — `K8sAdapter::try_default` (KUBECONFIG → ~/.kube/config → in-cluster ServiceAccount), `list_pods` / `list_services`. dispatch.rs 2 K8s arms. `--k8s-enable` / `--k8s-namespace` flags. Audit: `K8sQueryServed`.
- 437 unit tests total.

### Added — Phase 9 (Stabilization + Cluster Gossip + Leptos SPA + Overlayfs Real Mount)

- **CI matrix** — stable + MSRV baseline. release.yml. 5 criterion benches. architecture.md (mermaid). 8 ADR. 5 scenarios. CONTRIBUTING.
- **linpodx-cluster** (NEW crate) — P2P gossip (HTTP `GET /api/v1/version` ping, alive→stale→dead 전이) + container view aggregation. transport via Phase 7 remote.
- **linpodx-webui** (NEW crate) — leptos 0.7 cdylib SPA. daemon build.rs LINPODX_WASM stub fallback. `?legacy=1` vanilla 폴백.
- **Overlayfs real mount** (`linpodx-runtime::overlayfs`) — fuse-overlayfs + MountedRoot RAII. **BtrfsBackend** real subvolume.
- 422 unit tests total.

### Added — Phase 8 (Web UI v1 + Remote mTLS + Overlayfs Real Implementation)

- **Embedded read-only Web UI** (`linpodx-daemon::web_ui`) — axum REST + vanilla JS @ `/ui/*` + `/api/v1/*` with bearer auth.
- **mTLS for remote daemon** — rustls + axum-server tls-rustls-no-provider + WebPkiClientVerifier + x509-parser CN. CLI wss client.
- **OverlayfsBackend 실 구현** (`linpodx-runtime/src/overlayfs.rs`) — store_root + meta.json + `podman cp` commit + `cp -al` tag.
- 392 unit tests total.

### Added — Phase 7 (Pluggable Snapshot Backend + Diff_v2 + Plugin v2 + WS Remote)

- **Pluggable `SnapshotBackend` trait** — PodmanCommit + Overlayfs/Btrfs scaffolds.
- **OCI layer-aware `diff_v2`** + plugin v2 extension points (`audit_filter` chain + `profile_validator`).
- **cgroup v2 metrics** + WebSocket remote daemon (axum + bearer token).
- 359 unit tests total.

### Added — Phase 6 (WASM Plugin SDK + Live Container Metrics)

- **WASM plugin SDK** (`linpodx-plugin`) — wasmtime v26 + `PluginAwareApprovalGateway` short-circuit.
- **Live container metrics** — 1Hz `podman stats` collector + GUI sparkline tab.
- **Polish**: fork-on-write snapshot branch + MCP HashMap state.
- 307 unit tests total.

### Added — Phase 5 (L4 Egress Firewall + MCP Phase 2F + Snapshot Tree/Diff)

- **L4 egress firewall** — privileged `linpodx-netfilter-helper` + nftables, defence-in-depth socket auth.
- **MCP Phase 2F notifications** — subscribe / updated / list_changed + capability cache.
- **Snapshot tree/diff** — podman diff + branch alias + GUI tree.
- 274 unit tests total. l4_rules wire via session→profile accessor pair.

### Added — Phase 3 + 4 + 2E (GUI Passthrough + Multi-distro + Async Snapshot + MCP Policy)

- **GUI / device passthrough** (`linpodx-common::passthrough::PassthroughSpec`) — Wayland socket bind, X11 socket bind + `DISPLAY` / `XAUTHORITY`, audio (PipeWire / PulseAudio), GPU device passthrough (`/dev/dri`), DBus session bus, clipboard helper, HiDPI / theme env-var inheritance, optional host app-menu `.desktop` registration. Per-profile and per-container (`CreateOptions.passthrough`) merge at create time.
- **Multi-distro templates** (`linpodx-distro`) — 6 templates: Ubuntu, Fedora, Arch, Debian, Alpine, NixOS. Each carries `default_image`, `init_kind` (`none` / `systemd` / `openrc`), `default_packages`, `recommended_passthrough`, `default_shell`. New IPC: `DistroTemplateList`, `DistroTemplateInspect`, `DistroCreate`, `DistroBuild`, `DistroEnter`, `DistroRemove`. Persistent VM-mode (`--vm-mode`) provisions a `linpodx-distro-<name>-home` volume, auto-restart, and `--userns=keep-id` for 1:1 host-UID/GID mapping.
- **systemd-in-container** — `CreateOptions.systemd` and `SandboxProfile.systemd` translate to `podman create --systemd=true`. Required for the Ubuntu / Fedora / Debian VM-mode templates.
- **MCP per-method policy** (`linpodx-common::ipc::McpPolicyRule` / `McpPolicyDecision`) — every JSON-RPC method/tool pair maps to one of `auto_allow` / `prompt` / `deny` / `audit_only`. `prompt` decisions go through the existing approval gateway with the `McpTool` category. Migrations `0007_mcp_policy.sql`. New IPC: `McpPolicyList`, `McpPolicySet` (upsert + optional `replace_all`).
- **Async snapshot jobs** (`linpodx-common::ipc::SnapshotJobCreate / SnapshotJobStatus`) — non-blocking `podman commit` with `EventKind::Progress` events and a terminal `Succeeded` / `Failed`. Migrations `0008_snapshot_jobs.sql`. Fits the GUI's "kick off a snapshot, keep using the app" UX.
- **Network egress allowlist enforcement** — runtime team's hickory-DNS proxy returns `NXDOMAIN` for non-allowlisted hostnames; sandbox profiles' `network: kind: allowlist` is now enforced (best-effort, DNS-only, won't catch raw-IP egress).
- **Approvals subscribe** (`Method::ApprovalsSubscribe`) — server-handled stream just for approval requests; lets the GUI approval modal subscribe without joining the firehose `Subscribe` channel.
- **CLI: 14 new commands** (`linpodx-cli`): distro, passthrough, network egress, snapshot job, and MCP policy command groups.
- New CLI table formatters: `print_distro_template_list`, `print_distro_instance`, `print_mcp_policy_list`, `print_snapshot_job_status`, `print_passthrough_status` (toggles rendered with `[x]` / `[ ]`).
- **5 example sandbox profiles** (`examples/profiles/`): `gui-full.yaml`, `gui-no-gpu.yaml`, `distro-ubuntu-vm.yaml`, `distro-alpine-cli.yaml`, and `mcp-strict.yaml`.
- **5 new live integration test files** (`#[ignore]`-gated): passthrough, distro, MCP policy, network egress, and async snapshot lifecycle coverage.
- New CLI dep: `serde_yml` (workspace-pinned 0.0.12, MIT/Apache).

### Added — Phase 2B / 2C / 2D (Snapshot + Session + MCP Bridge)

- **Snapshot manager** (`linpodx-sandbox::snapshot`) on top of new `linpodx-runtime::snapshot` (`podman commit` / `inspect` / `rmi`). Snapshots are tagged `linpodx-snap-<seq>` and tracked in a new SQLite table (migration `0004_snapshots.sql`) with `parent_id` lineage and per-snapshot size. Pre-run snapshot path is wired through `SandboxManager::pre_run_snapshot` so profiles can opt in.
- **Session manager** (`linpodx-sandbox::session`) opens a row in `mcp_sessions` (migration `0005_sessions.sql`) on container create, closes it on remove. `timeline` merges `audit_log` + `mcp_events` chronologically, scoped to the session's container + time window. `ContainerRemove` now resolves the user-supplied id/name to the canonical container id before calling `session.end` so removal-by-name closes the right row.
- **MCP host-stdio bridge** — new `linpodx-mcp` crate (`BridgeRegistry::start/stop/status`). Spawns a host MCP server process + `podman exec -i <container>`, pumps stdio in both directions, best-effort JSON-RPC `method` extraction, allowlist enforcement (empty = audit-only). Each line audited via `mcp_events` (migration `0006_mcp_events.sql`) using new `linpodx-common::audit_sink::{AuditSink, AuditSinkKind}` so the sandbox + bridge stay decoupled.
- IPC: 12 new `Method` variants. Snapshot — `SnapshotCreate / List / Inspect / Rollback / Remove / Prune`. Session — `SessionList / Inspect / Timeline`. MCP — `McpBridgeStart / Stop / Status`. Plus typed responses (`SnapshotSummary`, `SnapshotCreateResponse`, `SnapshotRollbackResponse`, `SnapshotPruneResponse`, `SessionSummary`, `SessionTimelineEntry`, `McpBridgeStartResponse`, `McpBridgeStopResponse`, `McpBridgeStatusEntry`). `IPC_VERSION` stays at 1 (additive only).
- New `EventTopic` variants `Snapshot`, `Session`, `Mcp` (3 added; `EventTopic::ALL` is now 9). New `AuditKind` variants (9): `SnapshotCreated`, `SnapshotRolledBack`, `SnapshotRemoved`, `SessionStarted`, `SessionEnded`, `McpBridgeStarted`, `McpBridgeStopped`, `McpToolCalled`, `McpToolDenied`. New `ApprovalCategory::McpTool` so future profiles can gate individual MCP method calls. Phase 2A follow-up: `approval_resolved` notification fan-out so sibling listeners can dismiss prompts when another listener answered.
- CLI: 3 new subcommand groups + 12 client wirings: `linpodx snapshot`, `linpodx session`, and `linpodx mcp`.
- New table formatters in `linpodx-cli::output`: `print_snapshot_list`, `print_session_list`, `print_session_timeline` (one chronological line per entry), `print_mcp_status`.
- New live integration tests (`#[ignore]`-gated; require Podman ≥ 4.6.0): snapshot lifecycle, session lifecycle, and MCP bridge lifecycle.
- 95 unit tests total (Phase 2A 73 → 95). Targets reached: 18 ignored integration tests passing locally with Podman 5.8.1; 2 runtime/snapshot checks remained runtime-team follow-up at that point.

### Added — Phase 2A (Approval Gates)

- New `linpodx-common::approval` module: `ApprovalCategory` enum (`MountHostPath`, `CapAdd`), `ApprovalRequest`, `ApprovalOutcome` (Granted / Denied / TimedOut / NoListener), object-safe `ApprovalGateway` trait + `NoopApprovalGateway` / `DenyAllApprovalGateway` for tests.
- `SandboxProfile` extended with `approval_gates: Vec<ApprovalCategory>` (default empty — Phase 1C profiles unchanged) and `approval_timeout_secs: Option<u64>` (per-profile override; global default 30 s).
- `PolicyDecision::NeedsApproval` variant — when a profile has the matching gate enabled, mount/cap-add violations now produce a list of `PendingGate`s instead of an immediate `Deny`.
- `SandboxManager` carries `Arc<dyn ApprovalGateway>`; `apply_to_create` resolves each gate via the gateway, audits per-step (`ApprovalRequested` → `ApprovalGranted` / `ApprovalDenied` / `ApprovalTimedOut` / `ApprovalNoListener`), then proceeds or denies.
- New `linpodx-daemon::approval::ApprovalRegistry` — broadcast channel + pending-request HashMap. Implements `ApprovalGateway`. Fans out requests to subscribed connections; `respond` resolves the pending oneshot. Cleans up on timeout to avoid memory leaks.
- IPC: new `Method::ApprovalDecision` (client → server) and a server-pushed `Notification` with method `"approval_request"`. `IPC_VERSION` stays at 1 (additive only).
- `server.rs` gains an approval-broadcast subscription per connection (active when the connection has called `Subscribe`); `tokio::select!` adds a fourth branch fanning approval requests to the listener as `ServerMessage::Notification`.
- `Client::next_server_message` (generic) extracted out of `next_event` so callers can demultiplex multiple notification kinds. `next_event` now delegates and skips non-`event` notifications.
- New CLI subcommand `linpodx approvals [--json]` — interactive listener that subscribes, prompts the user (Y/N) on `approval_request`, and replies via `ApprovalDecision`. Defaults to "deny" on stdin timeout / EOF.
- `examples/profiles/interactive-mounts.yaml` — baseline profile demonstrating gated mounts and gated cap_add.
- New live integration tests `crates/linpodx-daemon/tests/e2e_approvals.rs` (4 scenarios, `#[ignore]`-gated): `approval_granted_path`, `approval_denied_path`, `approval_no_listener`, `approval_chain_intact_after_round_trip`. Uses an in-process auto-responder that subscribes and replies with a fixed decision.
- 73 unit tests total (Phase 1C 60 → 73). New: 5 common::approval (category serde / request serde / outcome serde / NoopGateway / DenyAllGateway), 5 daemon::approval::ApprovalRegistry, 3 sandbox::policy (NeedsApproval / cap-add gate / Phase 1C compat).
- Total ignored integration tests: 15 (was 11; +4 from `e2e_approvals`).

### Added — Phase 1C (Sandbox v0.1)

- `linpodx-sandbox` is now a real implementation, not a placeholder. Modules: `schema` (typed YAML profile), `profile` (loader), `policy` (`apply` pure function), `audit` (SHA-256 hash chain), `manager` (`SandboxManager` orchestrator).
- YAML profile schema (`version: 1`): network policy (`none` / `allowlist` / `full`), mount whitelist (named volumes or absolute host paths), capability drop/add, CPU/memory caps, read-only rootfs, plus `disk_mb` / `time_secs` recorded for forward compat.
- Policy engine enforces (Phase 1C): cap-drop / cap-add, network=none, mount whitelist (deny on violation), read-only rootfs, CPU + memory caps. Recorded but not enforced: network egress allowlist, disk_mb, time_secs (Phase 3).
- Tamper-evident audit log: `audit_log` SQLite table, `this_hash = sha256(prev_hash || serialized_payload)`. `linpodx sandbox verify` walks the chain and reports the first divergent seq.
- New IPC methods: `SandboxProfileList`, `SandboxProfileGet`, `SandboxProfileReload`, `AuditLogQuery`, `AuditLogVerify`. New event topics `EventTopic::Sandbox`, `EventTopic::Audit` (Phase 1B `EventTopic::ALL` updated). All additive — `IPC_VERSION` stays at 1.
- `linpodx-common::events::EventPublisher` trait — object-safe abstraction so `linpodx-sandbox` can emit events without depending on the daemon-internal `EventBus`. The daemon's `EventBus` implements it.
- `CreateOptions` extended with 6 new fields (`cap_drop`, `cap_add`, `read_only`, `cpus`, `memory_mb`, `sandbox_profile`). All `#[serde(default)]` so old clients still parse.
- `Podman::create` translates the new fields to `--cap-drop`, `--cap-add`, `--read-only`, `--cpus`, `--memory <N>m`.
- CLI: new `linpodx sandbox {list, show, reload, apply, audit, verify}` subcommand group + `--sandbox <profile>` flag on `linpodx run`.
- Baseline profiles in `examples/profiles/` for read-only networking, generic CLI automation, GUI passthrough, interactive mounts, strict bridge policy, and distro workflows.
- New live integration tests `crates/linpodx-daemon/tests/e2e_sandbox.rs` (3 scenarios, `#[ignore]`-gated): apply-allow path with audit verification, apply-deny path on mount violation, hash-chain verify + tamper detection.
- Daemon's `looks_like_not_found` heuristic tightened — only matches "no such container/image/volume/network", not generic "no such file" (was incorrectly mapping cgroup probe failures to NotFound).
- 60 unit tests total (Phase 1B 40 → 60). New: 3 schema, 4 profile loader, 7 policy, 6 audit (hash chain + tamper detection).
- New deps: `serde_yml` (MIT/Apache, maintained fork of unmaintained `serde_yaml`) and `sha2` (MIT/Apache).

### Added — Phase 1B (Event Bus + iced GUI)

- `linpodx-common::ipc`: `ServerMessage` (`#[serde(untagged)]` Response | Notification), `Notification` (JSON-RPC 2.0 server-push), `Subscribe` Method variant + `SubscribeParams` + `SubscribeResponse` typed alias, `Event` / `EventTopic` (Container / Image / Volume / Network) / `EventKind` (Created / Started / Stopped / Removed / Renamed / Pulled / Tagged) types. `IPC_VERSION` stays at 1 (additive).
- `linpodx-daemon`: new `event_bus.rs` (broadcast channel, default capacity 1024). `Dispatcher` carries an `Arc<EventBus>` and publishes after each successful state-changing operation (~10 publish sites). `server.rs` rewritten with `tokio::select!` interleaving — same Unix socket connection multiplexes one-shot RPC and a long-lived event subscription, with topic filtering per connection. Subscribe is intercepted at the server layer (returns ack immediately, then streams `ServerMessage::Notification` for matching events).
- `linpodx-cli`: new `events` subcommand. `--topic <container|image|volume|network>` (repeatable; default = all), `--json` for raw output. Human format: `[HH:MM:SS] container.started id=abc123… details={"image":...}`. `Client::next_event()` reads server-pushed notifications, ignoring spurious responses.
- `linpodx-gui` (new binary): iced 0.13-based read-only dashboard. Four tabs (Containers / Images / Volumes / Networks) with live updates: subscribes to all topics on connect, reuses `*List` calls to refresh the affected tab on each event. Reconnects with exponential backoff (1s → 30s) on daemon disconnect; red banner shows connection state. Pure-state reducer (`linpodx_gui::state::App::apply`) is unit-testable.
- New live integration test `crates/linpodx-daemon/tests/e2e_events.rs` (`#[ignore]`-gated): spawns daemon, runs `linpodx events --json --topic container` in background, drives container lifecycle via CLI, asserts `created`/`started`/`removed` notifications appear. Verified locally with Podman 5.8.1.
- 40 unit tests total (was 27): +5 IPC envelope serde tests (ServerMessage discrimination, Notification roundtrip, EventTopic snake_case, EventTopic::parse aliases, Subscribe serialization), +3 event-bus filtering tests, +5 GUI state-reducer tests.
- iced workspace dependency added (MIT, `tokio` feature). First build is slow (wgpu / fontdb / smithay deps).

### Added — Phase 1A (Resource Management)

- `linpodx-common::state`: 9 new resource types (`ImageSummary`, `ImageInspect`, `ImageConfig`, `VolumeSummary`, `VolumeInspect`, `NetworkSummary`, `NetworkInspect`, `PortMapping`, `PortProtocol`) plus `VolumeMount`. Permissive serde with `#[serde(default)]` + `raw` field for forward compat.
- `linpodx-common::ipc`: 14 new `Method` variants (image / volume / network operations), 9 new typed response aliases. `CreateOptions` extended with `port_mappings`, `volumes`, `networks`. `IPC_VERSION` stays at 1 (additive change).
- `linpodx-runtime`: 3 new modules — `image::{list, pull, remove, inspect, tag}`, `volume::{list, create, remove, inspect, prune}`, `network::{list, create, remove, inspect, prune}`. `Podman::create` now passes `--publish`, `--volume`, `--network` flags to podman.
- `linpodx-cli`: 3 new subcommand groups — `linpodx images {ls,pull,rm,inspect,tag}`, `linpodx volume {ls,create,rm,inspect,prune}`, `linpodx network {ls,create,rm,inspect,prune}`. `linpodx run` extended with `-p / --publish`, `-v / --volume`, `--network`. New table formatters with human-readable sizes for image listings.
- 4 new `#[ignore]`-gated live integration tests (`images_lifecycle`, `volumes_lifecycle`, `networks_lifecycle`, `port_mapping`) covering the full CLI → daemon → podman path on a disposable scratch root.
- 27 unit tests total (was 14): port-mapping parser variants, volume-mount parser, IPC roundtrip, image/volume/network parser fixtures.

### Added — Phase 0 (Foundation)

- Cargo workspace skeleton: 6 crates (`linpodx-common`, `linpodx-runtime`, `linpodx-sandbox`, `linpodx-daemon`, `linpodx-cli`, `linpodx-gui`), `rust-toolchain.toml` (stable, MSRV baseline), `deny.toml` license whitelist, workspace deps.
- `linpodx-common`: shared types (`ContainerId`, `ImageId`, `VolumeId`, `NetworkId`), JSON-RPC 2.0 IPC envelope + `Method` enum, container state types, SQLite/`sqlx` infrastructure with migration runner, version constants (`LINPODX_VERSION`, `IPC_VERSION`).
- `linpodx-runtime`: Podman adapter via `tokio::process::Command` — `list` / `inspect` / `create` / `start` / `stop` / `remove` / `pull` / `logs`. Minimum Podman version check (≥ 4.6.0). Permissive JSON parsing tolerant of cross-version Podman output differences.
- `linpodx-daemon`: Unix-socket NDJSON server, JSON-RPC dispatch to runtime, `--podman-root`/`--podman-runroot` flags for sandboxing, graceful shutdown on SIGTERM/SIGINT, structured logging via `tracing`.
- `linpodx-cli`: `clap` derive subcommands (`ps`, `run`, `start`, `stop`, `rm`, `inspect`, `logs`, `version`), table / JSON output formats, actionable error if daemon unreachable.
- Integration test (`#[ignore]` gated) that spawns the real daemon + drives it via the real CLI, validating the full lifecycle against rootless Podman in a disposable scratch root.
- GitHub Actions CI: lint (fmt + clippy `-D warnings`), test (stable + MSRV baseline), doc, daily security audit (`cargo audit`, `cargo deny check`).
- Project vision and scope documentation, GitHub standard files, and MIT License.
