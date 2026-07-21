# 변경 이력

[English](../CHANGELOG.md) | **한국어**

이 프로젝트의 주요 변경 사항은 이 문서에 기록됩니다.

형식은 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 기반으로 하며,
버전 정책은 [Semantic Versioning](https://semver.org/lang/ko/)을 지향합니다.

## [Unreleased]

<!--
새 버전 섹션은 `### Highlights` 로 시작합니다. GitHub Release 본문은
CHANGELOG.md 의 해당 버전 섹션을 그대로 사용합니다.
-->

## [0.1.1] - 2026-05-14

### Highlights

**보안 픽스 패치.** `wasmtime` 14 건 (CRITICAL 샌드박스 탈출
RUSTSEC-2026-0095 / -0096 포함), `hickory-proto` 기본 DoS
RUSTSEC-2026-0119, `time` 스택 고갈 RUSTSEC-2026-0009, `serde_yml`
unsoundness RUSTSEC-2025-0068 / -0067 등 총 18 건의 advisory 를 닫습니다.
공개 API 변경 없음.

- `wasmtime 26.0.1 → 43.0.2` — WebAssembly 플러그인 샌드박스를 CVE 가 없는
  릴리스 라인으로 이동. 24 LTS 브랜치는 Winch / pooling-allocator 6 건 백포트가
  없어 채택 불가. 43.x 는 linpodx-plugin 과 API 호환이며 다운스트림 코드 변경
  0건.
- `hickory-{resolver,server,proto} 0.24 → 0.25` — egress DNS 필터의 메시지
  인코딩 CPU 고갈을 닫음. `linpodx-netfilter::resolver` /
  `linpodx-runtime::network_filter` 를 신 `TokioResolver` 빌더 API 에 맞춤.
- `serde_yml → serde_norway` — `serde_yml` 은 RUSTSEC-2025-0068 로 upstream
  archived 되었고 unsound `libyml` (RUSTSEC-2025-0067) 을 끌고 있었습니다.
  `serde_norway` 는 `serde_yaml` 의 maintained 드롭인 fork. workspace dep +
  크레이트 manifest 4 + 소스 파일 6 (cli/main.rs,
  sandbox/{profile,schema,snapshot_trigger}.rs, cluster/k8s.rs) 수정.
- `time 0.3.45 → 0.3.47` — `cargo update -p time` 로 전이적 bump,
  x509-parser / rcgen 의 스택 고갈 DoS 차단.

### 변경됨

- 신규 `.cargo/audit.toml` 가 `deny.toml [advisories].ignore` 를 미러링하여
  CI 의 `rustsec/audit-check` 가 exit 0 로 끝납니다. 9 건의 근거 있는 waiver:
  hickory NSEC3 (DNSSEC 검증 미사용), hickory 인코더 DoS (loopback 전용
  forwarder), rsa Marvin (sqlx-mysql 은 `Cargo.lock` 에만 존재하고 컴파일
  그래프에 포함되지 않음 — workspace `sqlx` 는
  `default-features = false` + `runtime-tokio,sqlite,macros,migrate` 만
  사용), 그리고 전이적 unmaintained 크레이트들 (`backoff`, `instant`,
  `paste`, `rustls-pemfile`, `serial`, `lru` GUI 전용).
- `deny.toml` 에 `BSL-1.0` 과 `CDLA-Permissive-2.0` 을 허용 라이선스로
  추가 (Boost 라이선스 `ryu` / `clipboard-win` / `error-code` /
  `xxhash-rust`, 그리고 Mozilla CA-trust-store 데이터 크레이트
  `webpki-roots`). 사용하지 않는 `Unicode-DFS-2016` 제거. 상위 Cargo.toml
  에 `license = ` 필드가 없는 `jsonpath-rust` 는 LICENSE 파일이 MIT 라는
  근거로 `[[licenses.clarify]]` 를 통해 MIT 로 고정.

### 수정됨

- 43.x bump 로 `wasmtime` 14 건의 advisory 가 전부 닫혔습니다. v0.1.0 을
  prerelease 로 강등시킨 두 건의 CRITICAL 샌드박스 탈출 경로 포함.

## [0.1.0] - 2026-05-13

### Highlights

**linpodx의 첫 pre-alpha 릴리스입니다.** Linux-native 컨테이너 매니저,
AI 에이전트 샌드박스, 데스크톱 GUI, 원격 데몬, 플러그인 시스템, 멀티 디스트로
기반을 한 번에 제공합니다.

- 로컬 데몬 + Rust CLI + iced GUI 가 같은 JSON-RPC 표면을 공유합니다.
- 승인 게이트, 감사 로그, 세션, 스냅샷, 브리지 정책이 샌드박스 흐름에 연결됩니다.
- GUI 패스스루, 멀티 디스트로 템플릿, 원격 데몬 보안, 플러그인 서명, 클러스터 기반을 포함합니다.
- source installer / uninstaller 와 릴리스 artifact workflow 를 제공합니다.

### 추가됨

- 데몬, CLI, GUI, runtime, sandbox, common IPC, distro, MCP, network filtering, plugin, cluster, web UI 로 구성된 Rust workspace.
- rootless Podman 기반 컨테이너 / 이미지 / 볼륨 / 네트워크 관리.
- YAML sandbox profile, approval gate, hash-chain audit log, session timeline, snapshot lifecycle.
- Wayland / X11 / audio / GPU / DBus / clipboard / HiDPI passthrough.
- Ubuntu, Fedora, Arch, Debian, Alpine, NixOS distro template 과 VM mode.
- WebSocket remote daemon, mTLS, token auth, client certificate pinning, TOFU enrollment.
- Wasmtime plugin runtime, signed plugin verification, key revocation.
- source 기반 `install.sh` / `uninstall.sh`.
- Cargo 호환 SemVer, `vX.Y.Z` 공개 태그, `REL-vX.Y.Z` 릴리스 marker 태그 정책.

### 변경됨

- MSRV: 1.85.
- 릴리스 노트는 사용자 가시 기능 영역 중심으로 정리합니다.
- 버전 체계와 개발 흐름을 Rust/Cargo 호환 SemVer를 기준으로 고정합니다.

### 테스트

- `cargo test --workspace`: 829 passed / 0 failed / 54 ignored.

## 사전 릴리스 히스토리 (Phase 0..17)

### 추가됨 — Phase 17 (암호화 강화: Argon2id KDF + 스냅샷 키 회전 + TOFU 만료 + 클러스터 폐기 전파)

- **Argon2id 기반 스냅샷 KDF** (`linpodx-runtime::snapshot_crypto`) — OWASP 2023
  기준선 (m = 19 456 KiB, t = 2, p = 1). 신규 `Kdf` enum 두 변형:
  `Argon2id` (기본) / `Sha256Rounds-1k` (Phase 16 호환을 위한 legacy).
  workspace 의존성에 `argon2 = "=0.5.3"` (std) 추가.
- **스냅샷 키 회전 / 전체 재암호화** — 신규 `snapshot_key_rotation.rs` 의
  `rotate_snapshot_key` 와 `re_encrypt_all` 가 `blob.enc` + `meta.json` 을
  원자적으로 다시 씁니다. 신규 IPC: `SnapshotKeyRotate` /
  `SnapshotReEncryptAll`. CLI: `linpodx snapshot {key-rotate,
  re-encrypt-all}`.
- **샌드박스 자동 암호화 트리거** (`linpodx-sandbox::snapshot_trigger`) —
  `SnapshotEncryptor` trait + `AutoEncryptHook` + `SandboxProfile.
  auto_encrypt_snapshots` 필드 + 런타임 어댑터 `RuntimeSnapshotEncryptor`.
  main.rs 의 `make_encryptor` 가 데몬 부팅 시 어댑터를 주입. 신규 IPC:
  `SandboxSnapshotAutoTriggerStatus` / `SandboxSnapshotAutoTriggerEnable`.
- **TOFU 만료** (`linpodx-daemon::pin_store`) — `TofuMode` 에
  `enabled_at` 과 `max_age_secs` 추가. `should_enroll_at(now)` /
  `is_expired_at` / `record_expiry`. ws_handler 가 만료된 TOFU 모드를
  마주치면 `TofuExpired` 를 한 번만 감사 로그에 기록 후 거부. 신규 IPC:
  `DaemonPinClientTofuExpiryStatus` / `DaemonPinClientTofuExpirySet`.
  CLI: `linpodx daemon pin-client tofu --enable --expires-in <secs>`.
- **클러스터 전체 플러그인 키 폐기 전파** (`linpodx-cluster`) —
  `AppData::RevokePluginKey` 가 Raft 로그를 통해 흐르고, follower 가
  `PluginRevocationSink` 로 적용. `KeyRegistryRevocationSink` 와
  `KeyRegistry::apply_remote_revocation` (idempotent). 신규 IPC:
  `PluginKeyRevokePropagate`. leader → propose / follower → `not_leader`
  반환. CLI: `linpodx plugin key revoke --cluster-wide --fingerprint <fp>`.
- **bench-tools / tests 워크스페이스 크레이트** — 신규 `bench-tools` 와
  `tests` 워크스페이스 멤버. Criterion bench `phase17_crypto` 는 Argon2id 약
  18ms, AES-256-GCM 549 MiB/s @ 100MB 측정 (참고 수치). `tests/`
  phase17 통합 11 건 (7 unignored + 4 ignore stub).
- **GUI Phase 17 통합** — iced 메시지 +18 / 탭 +2 (PinnedClients / Plugins,
  총 11 탭). 데몬 측 REST 엔드포인트 4 + KDF 배지 + TOFU 카운트다운 +
  cluster-revoke 모달 + auto-encrypt 토글 + 단위 테스트 +49 건.
- **마이그레이션 `0017_phase17_schema.sql`** — `snapshots` 에
  `kdf_algorithm` / `kdf_params` / `rotated_from_snapshot_id` /
  `rotated_at` 컬럼 추가, `pinned_clients` 에 `tofu_expires_at` 컬럼 추가,
  신규 `plugin_key_revocations` 테이블 생성.
- 단위 테스트 총 829 / 0 failed / 54 ignored (Phase 16 710 → +119).

### 추가됨 — Phase 16 (클러스터 상태 복제 + 스냅샷 암호화 + 공급망 polish)

- **Raft 상태 머신 기반 클러스터 상태 복제** (`linpodx-cluster::election`) — Phase 14/15 의 leader-elect + 멀티 노드 membership 위에 진짜 application log + state machine 활성. `AppData` enum 3-variant (`Noop` / `ProposeContainer{node_id, container: ContainerSummary}` / `RemoveContainer{node_id, container_id}`). MemStore.containers `BTreeMap<(node_id, container_id), ContainerSummary>` + `apply_to_state_machine` 진짜 구현 (Phase 15 까지 빈 placeholder). SnapshotPayload 에 container map 포함, `install_snapshot` 복원. RaftNode helpers: `state_snapshot()` / `propose_container()` / `propose_container_remove()` / `is_leader()`. `ClusterContainerView` IPC 가 raft.last_applied>0 + non-empty 시 raft 우선, 아니면 기존 gossip aggregate 폴백 (backward compat). 신규 IPC: `ClusterStateGet` / `ClusterStateProposeContainer`. CLI: `linpodx cluster state {get, propose --node-id <n> --container-id <c> [--image <i>]}`. Audit: `ClusterStateApplied` / `ClusterStateProposeFailed`.
- **스냅샷 at-rest 암호화 (AES-256-GCM)** — 신규 `linpodx-runtime/src/snapshot_crypto.rs` (414L): Aes256Gcm round-trip, sha2 1000-round salted KDF, base64 raw-key path, OsRng nonce, `EncryptionConfig` + `KeySource` (Env/Passphrase/Explicit). 활성 조건: `LINPODX_SNAPSHOT_ENCRYPT_PASSPHRASE` 또는 `LINPODX_SNAPSHOT_KEY` env 둘 중 하나 set (둘 다 unset 면 미암호화 — backward compat). `SnapshotBackend` trait 에 `encryption_config(&self) -> Option<&EncryptionConfig>` (default None). PodmanCommitBackend 는 unit struct 유지 (sandbox API 호환) + 프로세스 전역 `active_encryption_config()` `OnceLock` cache. side-car 파이프라인: `encrypt_committed_image` (podman save → AEAD → atomic blob.enc + meta.json), `decrypt_and_load` (verify ciphertext sha256 → AEAD decrypt → podman load). 신규 마이그레이션 `0016_snapshot_encryption.sql`. 신규 IPC: `SnapshotEncryptionStatus`. CLI: `linpodx snapshot encryption-status <id>`. Audit: `SnapshotEncrypted` / `SnapshotDecryptFailed`.
- **플러그인 키 폐기 / 회전** (`linpodx-plugin::key_registry`) — `KeyRegistryError::Revoked` variant + `KeyRegistry::revoke(publisher, reason)` (`<publisher>.revoked` JSON marker idempotent) + `lookup()` 가 marker 인식 → Revoked + `list_keys() -> Vec<KeyEntry>`. 신규 IPC: `PluginKeyList` / `PluginKeyRevoke`. CLI: `linpodx plugin key {list, revoke <publisher> --reason <r>}`. Audit: `PluginKeyRevoked`.
- **Pin TOFU 자동 등록** (`linpodx-daemon::pin_store`) — `TofuMode { enabled, max_enrollments, current_count }`. `ws_handler` mismatch + `should_enroll()` 시 `pin_store.insert(fp, "tofu-auto")` + accept upgrade. cap 도달 시 latch off → 기존 403 path. 신규 IPC: `DaemonPinClientTofuEnable`. CLI: `linpodx daemon pin-client tofu {--enable [--max <N>], --disable}`. Audit: `WsClientCertTofuEnrolled`.
- **bench CI 멀티 플랫폼** — `.github/workflows/bench.yml` matrix.include 에 `platform: linux-aarch64, runner: ubuntu-24.04-arm` 추가.
- **Workspace deps**: `aes-gcm = "0.10"` + `rand = "0.8"`.
- 단위 테스트 총 710 (Phase 15 660 → +50 lib).

### 추가됨 — Phase 15 (클러스터 멀티 노드 + 플러그인 서명 + Polish)

- **클러스터 Raft 멀티 노드 활성** (`linpodx-cluster::election`) — RaftHttpFactory 활성. `start_with_network<F: RaftNetworkFactory>` + `add_learner_with_audit` / `promote_with_audit` / `remove_node` voter→demote audit. `membership_snapshot()`. 신규 `gossip::raft_membership_sync_round` + `run_raft_sync_loop` (5s 주기). main.rs 가 `--cluster-raft-advertise` 시 RaftHttpFactory wire. 신규 IPC: `ClusterRaftStatus` / `ClusterRaftPromote`. CLI: `linpodx cluster {status, promote <node_id>}`. Audit: `ClusterRaftPromoted` / `ClusterRaftDemoted`.
- **플러그인 ed25519 서명 검증** (`linpodx-plugin`) — 신규 `signing.rs` (verify_strict, malleable sig 거부) + `key_registry.rs` (4-tier resolution: env > XDG > HOME > /etc, ASCII-stem sanitiser). PluginManifest 에 `publisher` + `signature_b64`. plugin_store install path: params override > detached `signature.b64` > `manifest.signature_b64`. 검증 성공 → `PluginSignatureVerified`, 실패 → `PluginSignatureRejected` + ABORT. `LINPODX_ALLOW_UNSIGNED_PLUGINS in {1,true,yes}` escape hatch. CLI `linpodx plugin install --signature <p> --public-key <p>`. examples/plugins/signed-noop/ (NEW).
- **WS 클라이언트 cert pinning** (`linpodx-daemon`) — `--pin-clients` flag (mTLS 전제). 신규 `pin_store.rs` (sha256 leaf DER, PEM 재인코딩 안정). 신규 마이그레이션 `0015_pinned_clients.sql`. 신규 IPC: `DaemonPinClient{Add, List, Remove}`. ws_handler match → `WsClientCertPinned` audit + accept, miss → HTTP 403. CLI: `linpodx daemon pin-client {add <cert.pem> --label X, list, remove <fp>}`.
- **SELinux 런타임 fallback** — `LINPODX_SELINUX_RUNTIME_FALLBACK=1` 시 동적 .te 컴파일 실패 시 `selinux_static_label = Some("container_t")` substitute + `SelinuxLabelRuntimeFallback` audit.
- **bench CI per-platform baseline** — `.github/workflows/bench.yml` matrix-strategy `platform`-keyed (linux-x86_64), push-to-main 트리거, sticky PR comment per platform.
- 단위 테스트 총 660 (Phase 14 618 → +42 lib).

### 추가됨 — Phase 14 (보안 마무리 + WebUI 벤더링 + Push mTLS + 클러스터 Raft)

- **EgressEnforcer 플러그인 Deny 실제 강제** — Phase 13 audit-only chain 결과를 helper allowlist 에서 REMOVE (default `policy drop` take over). `EgressDenyEnforced` audit.
- **SELinux 정적 라벨 흐름** — `CompiledProfile.selinux_static_label: Option<String>`. `compile_selinux()` 가 `schema.selinux_label.is_some()` 시 동적 .te 파이프라인 SHORT-CIRCUIT. `to_security_opts()` 우선순위 = static > dynamic. `SelinuxStaticLabelApplied` audit.
- **WS Sec-WebSocket-Protocol 토큰** — `Bearer.<token>` (RFC 6455 dot-form) + `Bearer <token>` 모두 수용. `ws_handler` + `pty_ws_handler` 가 헤더 우선 → query string 폴백. echo response header. `WsAuthSubprotocol` audit.
- **xterm.js vendoring** — `LINPODX_VENDOR_XTERM=1` 빌드 토글. `linpodx-webui/build.rs` 가 ureq 2 로 jsDelivr 에서 다운로드 → OUT_DIR. daemon `/assets/*` 라우트.
- **이미지 push private registry mTLS** — `podman.rs::push()` 가 `cert_dir: Option<&Path>` → `--cert-dir <p>` argv. CLI `linpodx image push --cert-dir <p>`. `ImagePushTls` audit.
- **클러스터 Raft single-node leader-elect** — openraft 0.9.24 통합. `LinpodxRaft` `RaftTypeConfig`, `MemStore` (RaftStorage v1 → v2 Adaptor), `LeaderState`, `RaftNode` facade, `VoteSink` + `SqliteVoteSink`. background metric_pump 로 `ClusterLeaderElected` / `ClusterLeaderLost` audit. 신규 `raft_http.rs` (axum router /append/vote/snapshot + reqwest factory). main.rs `--cluster-raft` flag. 신규 IPC: `ClusterLeaderGet` / `ClusterRoleGet`. CLI: `linpodx cluster {leader, role}`. 신규 마이그레이션 `0014_raft_state.sql`.
- 단위 테스트 총 618 (Phase 13 545 → +73).

### 추가됨 — Phase 13 (K8s write-side + xterm.js Web UI + 플러그인 v3 Hooks)

- **K8s write-side** — `K8sAdapter` +4 메서드 (create_pod / delete_pod / create_namespace / scale_deployment). 신규 IPC 4. CLI: `linpodx k8s {pod create <yaml|->, pod delete <name>, ns create <name>, scale <deployment> --replicas <N>}`.
- **xterm.js Web UI 통합** — index.html 에 @xterm/xterm@5 + @xterm/addon-fit@0.10 jsDelivr CDN. 신규 `xterm.rs` safe Rust wrapper via js_sys::Reflect. LogsModal + ExecPtyModal (PtySocket Drop deterministic ws.close).
- **플러그인 SDK 추가 hooks** — `network_trace` + `runtime_injector` 2 hook. NetworkDecision (Allow/Deny/AuditOnly precedence Deny>AuditOnly>Allow). InjectorPayload concat-merge. ContainerCreate dispatch arm 가 evaluate_runtime_injector 호출 → opts.env/command/security_opts merge. 샘플 플러그인 2 (audit-egress + inject-tracing-env).
- 단위 테스트 총 545 (Phase 12 515 → +30).

### 추가됨 — Phase 12 (SELinux + Web UI Modals + 인터랙티브 PTY)

- **SELinux .te synthesis** — 동적 .te 생성 + `checkmodule + semodule_package + semodule -i`. `--security-opt label=type:<type>` security_opts 주입. graceful fallback. **목표 #5 보안 우선 100% 도달.**
- **Web UI per-row modals** — `ListTable` children-slot refactor + 3 신규 modal (exec / logs / push) wired into 4 view call-sites.
- **인터랙티브 PTY 프록시** — portable-pty 0.8 master/slave on the daemon + axum `/pty/<bridge_id>` WebSocket binary (query-string token). CLI `linpodx exec -i -t` over crossterm raw mode + `RawModeGuard` panic-safe.
- 단위 테스트 총 515.

### 추가됨 — Phase 11 (Secprofile 컴파일러 + Container Streaming + 이미지 Push)

- **Secprofile 컴파일러** — seccomp OCI JSON via seccompiler 0.5 + AppArmor text via `apparmor_parser -r`. `linpodx sandbox profile compile` CLI.
- **컨테이너 exec / 로그 스트리밍 / 이미지 pull progress** — 신규 `EventKind::Log`, GUI Exec/Logs modals + 1000-line ring. CLI `linpodx exec` / `linpodx logs -f` / `linpodx image pull`.
- **이미지 레지스트리 push + multi-arch manifest** — `podman push` (with `--creds`), `podman manifest create / add / push`. CLI: `linpodx image {push, manifest {create, push}}`.
- 단위 테스트 총 485.

### 추가됨 — Phase 10 (Polish + Diff_v2 file-changes + K8s read-only)

- **Polish 5 sub-tasks**: `CreateOptions.rootfs` 주입, WS `?token=<t>` query-string, `linpodx daemon cert generate` rcgen-based, Web UI v2 (cards + sort + filter + dark gradient via leptos `view!`), bench CI hook.
- **diff_v2 file-level diff** — 신규 `oci_tar.rs` (322L). `podman save -o` + manifest.json walk + .tar.gz auto-detect + .wh.* whiteout marker skip.
- **K8s read-only adapter** — `K8sAdapter::try_default` (KUBECONFIG 등), `list_pods` / `list_services`. dispatch.rs 2 K8s arms. `--k8s-enable` / `--k8s-namespace` flags.
- 단위 테스트 총 437.

### 추가됨 — Phase 9 (안정화 + 클러스터 Gossip + Leptos SPA + Overlayfs 실제 마운트)

- **CI matrix** — stable + MSRV 1.85. release.yml. 5 criterion benches. architecture.md (mermaid). 8 ADR. 5 scenarios. CONTRIBUTING.
- **linpodx-cluster** (NEW crate) — P2P gossip + container view aggregation.
- **linpodx-webui** (NEW crate) — leptos 0.7 cdylib SPA. daemon build.rs LINPODX_WASM stub fallback. `?legacy=1` vanilla 폴백.
- **Overlayfs 실제 마운트** — fuse-overlayfs + MountedRoot RAII. **BtrfsBackend** real subvolume.
- 단위 테스트 총 422.

### 추가됨 — Phase 8 (Web UI v1 + Remote mTLS + Overlayfs 실제 구현)

- **임베디드 read-only Web UI** — axum REST + vanilla JS @ `/ui/*` + `/api/v1/*` with bearer auth.
- **Remote daemon mTLS** — rustls + axum-server tls-rustls-no-provider + WebPkiClientVerifier + x509-parser CN. CLI wss client.
- **OverlayfsBackend 실제 구현** — store_root + meta.json + `podman cp` commit + `cp -al` tag.
- 단위 테스트 총 392.

### 추가됨 — Phase 7 (Pluggable Snapshot Backend + Diff_v2 + Plugin v2 + WS Remote)

- **Pluggable `SnapshotBackend` trait** — PodmanCommit + Overlayfs/Btrfs scaffolds.
- **OCI layer-aware `diff_v2`** + 플러그인 v2 hooks (`audit_filter` chain + `profile_validator`).
- **cgroup v2 metrics** + WebSocket remote daemon (axum + bearer token).
- 단위 테스트 총 359.

### 추가됨 — Phase 6 (WASM 플러그인 SDK + 라이브 컨테이너 메트릭)

- **WASM 플러그인 SDK** — wasmtime v26 + `PluginAwareApprovalGateway` short-circuit.
- **라이브 컨테이너 메트릭** — 1Hz `podman stats` collector + GUI sparkline tab.
- **Polish**: fork-on-write snapshot branch + MCP HashMap state.
- 단위 테스트 총 307.

### 추가됨 — Phase 5 (L4 Egress 방화벽 + MCP Phase 2F + 스냅샷 Tree/Diff)

- **L4 egress 방화벽** — privileged `linpodx-netfilter-helper` + nftables, defence-in-depth socket auth.
- **MCP Phase 2F notifications** — subscribe / updated / list_changed + capability cache.
- **스냅샷 tree/diff** — podman diff + branch alias + GUI tree.
- 단위 테스트 총 274.

### 추가됨 — Phase 3 + 4 + 2E (GUI 패스스루 + 멀티 디스트로 + 비동기 스냅샷 + MCP 정책)

- **GUI / 디바이스 패스스루** (`linpodx-common::passthrough::PassthroughSpec`) — Wayland 소켓 바인드, X11 소켓 바인드 + `DISPLAY` / `XAUTHORITY`, 오디오 (PipeWire / PulseAudio), GPU 패스스루 (`/dev/dri`), DBus 세션 버스, 클립보드 헬퍼, HiDPI / 테마 환경 변수 상속, 호스트 앱 메뉴 `.desktop` 등록 옵션. 프로필별 + 컨테이너별 (`CreateOptions.passthrough`) 가 create 시점에 머지.
- **멀티 디스트로 템플릿** (`linpodx-distro`) — 6 개 템플릿: Ubuntu, Fedora, Arch, Debian, Alpine, NixOS. 각 템플릿은 `default_image`, `init_kind` (`none` / `systemd` / `openrc`), `default_packages`, `recommended_passthrough`, `default_shell` 보유. 신규 IPC: `DistroTemplateList`, `DistroTemplateInspect`, `DistroCreate`, `DistroBuild`, `DistroEnter`, `DistroRemove`. VM 모드 (`--vm-mode`) 는 `linpodx-distro-<name>-home` 영구 볼륨 + auto-restart + `--userns=keep-id` (호스트 UID/GID 1:1 매핑) 제공.
- **systemd-in-container** — `CreateOptions.systemd` 와 `SandboxProfile.systemd` 가 `podman create --systemd=true` 로 변환. Ubuntu / Fedora / Debian VM 모드 템플릿에서 필수.
- **MCP 메서드별 정책** (`linpodx-common::ipc::McpPolicyRule` / `McpPolicyDecision`) — 모든 JSON-RPC 메서드/툴 쌍이 `auto_allow` / `prompt` / `deny` / `audit_only` 중 하나에 매핑. `prompt` 결정은 기존 approval gateway 의 `McpTool` 카테고리로 흐름. 마이그레이션 `0007_mcp_policy.sql`. 신규 IPC: `McpPolicyList`, `McpPolicySet` (upsert + 옵션 `replace_all`).
- **비동기 스냅샷 작업** (`linpodx-common::ipc::SnapshotJobCreate / SnapshotJobStatus`) — non-blocking `podman commit` + `EventKind::Progress` 이벤트 + 종착 `Succeeded` / `Failed`. 마이그레이션 `0008_snapshot_jobs.sql`. GUI "스냅샷 시작 후 계속 작업" UX 에 적합.
- **네트워크 egress allowlist 강제** — runtime 팀의 hickory-DNS 프록시가 비-allowlist 호스트에 `NXDOMAIN` 응답. 샌드박스 프로필의 `network: kind: allowlist` 가 이제 강제됨 (best-effort, DNS 전용; raw IP egress 는 잡지 못함).
- **승인 구독** (`Method::ApprovalsSubscribe`) — 승인 요청 전용 서버 처리 스트림. GUI 승인 모달이 `Subscribe` 의 전체 이벤트 스트림에 합류하지 않고도 구독 가능.
- **CLI: 14 개 신규 명령** (`linpodx-cli`):
  - `linpodx distro {list, create, build, enter, remove}` (5).
  - `linpodx passthrough {grant, revoke, status}` (3) — `SandboxProfileGet` 으로 프로필 YAML fetch → `passthrough:` 변경 → `--profiles-dir` 에 write back → `SandboxProfileReload` 호출.
  - `linpodx network egress {set, status}` (2) — 동일한 YAML 편집 + reload 패턴, `network:` 변경.
  - `linpodx snapshot job {start, status}` (2) — `SnapshotJobCreate` / `SnapshotJobStatus` wrap.
  - `linpodx mcp policy {set, list}` (2) — `McpPolicyList` / `McpPolicySet` wrap.
- 신규 CLI 테이블 포매터: `print_distro_template_list`, `print_distro_instance`, `print_mcp_policy_list`, `print_snapshot_job_status`, `print_passthrough_status` (토글은 `[x]` / `[ ]` 로 렌더링).
- **5 개 예시 샌드박스 프로필** (`examples/profiles/`):
  - `gui-full.yaml` — 전체 데스크톱 패스스루 (Wayland + X11 + 오디오 + GPU + DBus + 클립보드 + HiDPI).
  - `gui-no-gpu.yaml` — GPU 제외 동일.
  - `distro-ubuntu-vm.yaml` — `distro_kind: ubuntu`, `systemd: true`.
  - `distro-alpine-cli.yaml` — `distro_kind: alpine`, systemd / 패스스루 없음.
  - `mcp-strict.yaml` — 모든 `tools/call` 이 승인을 통과, 15초 타임아웃.
- **5 개 신규 라이브 통합 테스트** (`#[ignore]` 게이트):
  - `crates/linpodx-daemon/tests/e2e_passthrough.rs::passthrough_grant_revoke_roundtrip` — 임시 프로필 디렉토리 대상으로 grant + status + revoke.
  - `crates/linpodx-daemon/tests/e2e_distro.rs::distro_template_list_returns_six` + `distro_alpine_create_enter_remove_lifecycle`.
  - `crates/linpodx-daemon/tests/e2e_mcp_policy.rs::mcp_policy_set_then_list_roundtrip`.
  - `crates/linpodx-daemon/tests/e2e_network_egress.rs::network_egress_set_status_roundtrip`.
  - `crates/linpodx-daemon/tests/e2e_snapshot_async.rs::snapshot_job_lifecycle`.
  - 진행 중 팀의 `not yet implemented` placeholder 응답은 soft skip 으로 처리 → CLI 표면이 데몬-측 IPC backing 과 독립적으로 검증 가능.
- 신규 CLI 의존성: `serde_yml` (워크스페이스 핀 0.0.12, MIT/Apache).

### 추가됨 — Phase 2B / 2C / 2D (Snapshot + Session + MCP Bridge)

- **Snapshot 매니저** (`linpodx-sandbox::snapshot`) + 신규 `linpodx-runtime::snapshot` (`podman commit` / `inspect` / `rmi`). 스냅샷 이미지는 `linpodx-snap-<seq>` 로 태그되고 신규 SQLite 테이블 (`0004_snapshots.sql`) 에 `parent_id` 계보 + 크기와 함께 기록. `SandboxManager::pre_run_snapshot` 훅으로 프로필이 사전 스냅샷 옵션을 켤 수 있음.
- **Session 매니저** (`linpodx-sandbox::session`) — 컨테이너 create 시점에 `mcp_sessions` (`0005_sessions.sql`) 에 row 오픈, remove 시 종료. `timeline` 이 세션의 컨테이너/시간 범위로 `audit_log` + `mcp_events` 를 시간순 병합. `ContainerRemove` 가 사용자가 넘긴 id/name 을 canonical container id 로 resolve 한 뒤 `session.end` 호출 → 이름으로 삭제해도 정상 종료.
- **MCP host-stdio 브리지** — 신규 `linpodx-mcp` 크레이트 (`BridgeRegistry::start/stop/status`). 호스트 MCP 서버 프로세스 + `podman exec -i <container>` 를 spawn 후 양방향 stdio pump, JSON-RPC `method` best-effort 추출, allowlist 강제 (빈 allowlist = audit-only). 라인 단위 audit 가 `mcp_events` (`0006_mcp_events.sql`) 에 기록되며 신규 `linpodx-common::audit_sink::{AuditSink, AuditSinkKind}` 가 sandbox / 브리지 결합도를 분리.
- IPC: 12 개 신규 `Method` 변형. Snapshot — `SnapshotCreate / List / Inspect / Rollback / Remove / Prune`. Session — `SessionList / Inspect / Timeline`. MCP — `McpBridgeStart / Stop / Status`. 그리고 typed responses (`SnapshotSummary`, `SnapshotCreateResponse`, `SnapshotRollbackResponse`, `SnapshotPruneResponse`, `SessionSummary`, `SessionTimelineEntry`, `McpBridgeStartResponse`, `McpBridgeStopResponse`, `McpBridgeStatusEntry`). `IPC_VERSION` 1 유지 (additive).
- 신규 `EventTopic` 변형 `Snapshot`, `Session`, `Mcp` (3 추가; `EventTopic::ALL` 은 이제 9). 신규 `AuditKind` 변형 9 개: `SnapshotCreated`, `SnapshotRolledBack`, `SnapshotRemoved`, `SessionStarted`, `SessionEnded`, `McpBridgeStarted`, `McpBridgeStopped`, `McpToolCalled`, `McpToolDenied`. 신규 `ApprovalCategory::McpTool` — 향후 프로필이 개별 MCP 메서드 호출을 gate 가능. Phase 2A 후속: `approval_resolved` notification fan-out — 다른 listener 가 응답 시 prompt dismiss.
- CLI: 3 개 신규 서브커맨드 그룹 + 12 개 클라이언트 wiring.
  - `linpodx snapshot {create, list, inspect, rollback, rm, prune}` — `--label`, `--container`, `--new-name`, `--keep-original`, `--force`, `--keep-recent`.
  - `linpodx session {list, inspect, timeline}` — `--container`, `--limit`, 반복 가능 `--kind` 필터.
  - `linpodx mcp {start, stop, status}`. `start` 는 `<container> <host_command> [args...]` + 반복 가능 `--allow <method>`; trailing arg 은 host command 로 전달.
- 신규 테이블 formatter (`linpodx-cli::output`): `print_snapshot_list`, `print_session_list`, `print_session_timeline` (시간순 한 줄/엔트리), `print_mcp_status`.
- 신규 라이브 통합 테스트 (`#[ignore]` 게이트, Podman ≥ 4.6.0 필요):
  - `crates/linpodx-daemon/tests/e2e_snapshot.rs::snapshot_lifecycle` — create → list → inspect → audit (`snapshot_created`) → rm → list-empty.
  - `crates/linpodx-daemon/tests/e2e_session.rs::session_lifecycle` — alpine true 실행 → session list (active) → rm → session list (ended, ended_at 채워짐) → timeline 에 `session_started` 포함.
  - `crates/linpodx-daemon/tests/e2e_mcp.rs::mcp_bridge_lifecycle` — alpine sleep 30 + `mcp start /bin/cat` → status row → audit (`mcp_bridge_started`) → stop → audit (`mcp_bridge_stopped`).
- 단위 테스트 95 개 (Phase 2A 73 → 95). 목표 달성: Podman 5.8.1 로컬에서 통합 테스트 18 개 통과 (e2e_approvals 4, e2e_events 1, e2e_resources 4, e2e_sandbox 3, end_to_end 1 + 신규 e2e_snapshot / e2e_session / e2e_mcp 1 개씩 + runtime/podman_lifecycle 2). runtime/snapshot 단위 테스트 2 개 (NotFound 매핑) 는 runtime 팀 영역으로 미해결.

### 추가됨 — Phase 2A (Approval Gates)

- 신규 `linpodx-common::approval` 모듈: `ApprovalCategory` 열거형 (`MountHostPath`, `CapAdd`), `ApprovalRequest`, `ApprovalOutcome` (Granted / Denied / TimedOut / NoListener), object-safe `ApprovalGateway` trait + 테스트용 `NoopApprovalGateway` / `DenyAllApprovalGateway`.
- `SandboxProfile` 확장: `approval_gates: Vec<ApprovalCategory>` (기본 빈 — Phase 1C 프로필 동작 그대로) + `approval_timeout_secs: Option<u64>` (프로필별 오버라이드, 글로벌 기본 30초).
- `PolicyDecision::NeedsApproval` 변형 추가 — 매칭 게이트가 활성화된 프로필은 mount/cap-add 위반 시 즉시 Deny 대신 `PendingGate` 목록 반환.
- `SandboxManager` 가 `Arc<dyn ApprovalGateway>` 를 가지고 `apply_to_create` 가 게이트마다 gateway 호출, 단계별로 audit (`ApprovalRequested` → `ApprovalGranted` / `Denied` / `TimedOut` / `NoListener`) 기록 후 진행 또는 거부.
- 신규 `linpodx-daemon::approval::ApprovalRegistry` — broadcast 채널 + pending-request HashMap. `ApprovalGateway` 구현. 요청을 구독 연결로 fan-out, `respond` 가 pending oneshot 해결. timeout 시 메모리 누수 방지를 위한 cleanup.
- IPC: 신규 `Method::ApprovalDecision` (클라이언트 → 서버) + 서버 푸시 `Notification` (method `"approval_request"`). `IPC_VERSION` 은 1 유지 (additive).
- `server.rs` 가 연결마다 approval-broadcast 구독 (Subscribe 호출 후 활성). `tokio::select!` 의 네 번째 분기가 approval 요청을 `ServerMessage::Notification` 으로 listener 에 전달.
- `Client::next_server_message` (제네릭) 를 `next_event` 에서 추출 — caller 가 여러 종류의 notification 을 분기 처리 가능. `next_event` 는 위임하고 비-event notification 은 skip.
- 신규 CLI 서브커맨드 `linpodx approvals [--json]` — 인터랙티브 listener: 구독 후 `approval_request` 받으면 사용자에게 Y/N prompt, `ApprovalDecision` 으로 회신. stdin timeout / EOF 시 deny 기본값.
- `examples/profiles/interactive-mounts.yaml` — gated mounts / gated cap_add 시연 baseline.
- 신규 라이브 통합 테스트 `crates/linpodx-daemon/tests/e2e_approvals.rs` (4 시나리오, `#[ignore]` 게이트): `approval_granted_path`, `approval_denied_path`, `approval_no_listener`, `approval_chain_intact_after_round_trip`. In-process auto-responder 가 구독 + 고정 결정 회신.
- 단위 테스트 73 개 (Phase 1C 60 → 73). 신규: common::approval 5 개 (카테고리 serde / 요청 serde / outcome serde / NoopGateway / DenyAllGateway), daemon::approval 5 개 (ApprovalRegistry), sandbox::policy 3 개 (NeedsApproval / cap-add gate / Phase 1C 호환).
- 통합 테스트 총 15 개 (Phase 1C 11 → 15; +4 `e2e_approvals`).

### 추가됨 — Phase 1C (샌드박스 v0.1)

- `linpodx-sandbox` 가 placeholder 에서 본격 구현으로 전환. 모듈: `schema` (typed YAML 프로필), `profile` (로더), `policy` (`apply` 순수 함수), `audit` (SHA-256 해시 체인), `manager` (`SandboxManager` 오케스트레이터).
- YAML 프로필 스키마 (`version: 1`): 네트워크 정책 (`none` / `allowlist` / `full`), 마운트 화이트리스트 (named 볼륨 또는 절대 호스트 경로), capability drop/add, CPU / 메모리 캡, read-only rootfs. `disk_mb` / `time_secs` 는 forward-compat 으로 기록만.
- 정책 엔진 강제 (Phase 1C): cap-drop / cap-add, network=none, 마운트 화이트리스트 (위반 시 거부), read-only rootfs, CPU + 메모리 캡. 기록만 (Phase 3 강제): network egress allowlist, disk_mb, time_secs.
- 변조 감지 가능한 감사 로그: `audit_log` SQLite 테이블, `this_hash = sha256(prev_hash || serialized_payload)`. `linpodx sandbox verify` 가 체인을 재계산하고 첫 손상 seq 를 보고.
- 신규 IPC 메서드: `SandboxProfileList`, `SandboxProfileGet`, `SandboxProfileReload`, `AuditLogQuery`, `AuditLogVerify`. 신규 이벤트 토픽 `EventTopic::Sandbox`, `EventTopic::Audit` (Phase 1B `EventTopic::ALL` 갱신). 모두 additive — `IPC_VERSION` 은 1 유지.
- `linpodx-common::events::EventPublisher` trait — object-safe 추상화로 `linpodx-sandbox` 가 데몬 내부 `EventBus` 에 직접 의존하지 않음. 데몬의 `EventBus` 가 trait 구현.
- `CreateOptions` 6 필드 추가 (`cap_drop`, `cap_add`, `read_only`, `cpus`, `memory_mb`, `sandbox_profile`). 모두 `#[serde(default)]` → 기존 클라이언트 호환.
- `Podman::create` 가 새 필드를 `--cap-drop`, `--cap-add`, `--read-only`, `--cpus`, `--memory <N>m` 으로 변환.
- CLI: 신규 `linpodx sandbox {list, show, reload, apply, audit, verify}` 서브커맨드 그룹 + `linpodx run` 에 `--sandbox <profile>` 플래그.
- `examples/profiles/` 에 read-only networking, generic CLI automation, GUI passthrough, interactive mounts, strict bridge policy, distro workflow baseline profile 추가.
- 신규 라이브 통합 테스트 `crates/linpodx-daemon/tests/e2e_sandbox.rs` (3 시나리오, `#[ignore]` 게이트): apply-allow + audit 검증, apply-deny (mount 위반), 해시 체인 verify + 변조 감지.
- 데몬의 `looks_like_not_found` 휴리스틱 강화 — "no such container/image/volume/network" 만 매칭, 일반 "no such file" 은 제외 (cgroup probe 실패가 잘못 NotFound 로 매핑되던 버그 수정).
- 단위 테스트 60 개 (Phase 1B 40 → 60). 신규: schema 3, profile 로더 4, policy 7, audit 6 (해시 체인 + 변조 감지).
- 신규 의존성: `serde_yml` (MIT/Apache, unmaintained `serde_yaml` 의 maintained fork), `sha2` (MIT/Apache).

### 추가됨 — Phase 1B (이벤트 버스 + iced GUI)

- `linpodx-common::ipc`: `ServerMessage` (`#[serde(untagged)]` Response | Notification), `Notification` (JSON-RPC 2.0 server-push), `Subscribe` Method 변형 + `SubscribeParams` + `SubscribeResponse` typed alias, `Event` / `EventTopic` (Container/Image/Volume/Network) / `EventKind` (Created/Started/Stopped/Removed/Renamed/Pulled/Tagged) 타입. `IPC_VERSION` 은 1 유지 (additive).
- `linpodx-daemon`: 신규 `event_bus.rs` (broadcast 채널, 기본 capacity 1024). `Dispatcher` 가 `Arc<EventBus>` 를 가지고 상태 변경 메서드 성공 후 publish (publish 호출 ~10 곳). `server.rs` 재작성 — `tokio::select!` 인터리빙으로 같은 Unix 소켓 연결에서 일반 RPC + 장시간 이벤트 구독 동시 처리, 연결별 토픽 필터링. Subscribe 는 서버 레이어에서 인터셉트 (즉시 ack + 매칭 이벤트 `ServerMessage::Notification` 스트리밍).
- `linpodx-cli`: 신규 `events` 서브커맨드. `--topic <container|image|volume|network>` (반복 가능, 기본 = 전체), `--json` 로 raw 출력. 사람-읽기 형식: `[HH:MM:SS] container.started id=abc123… details={...}`. `Client::next_event()` 가 server-push notification 을 읽고 무관한 응답은 건너뜀.
- `linpodx-gui` (신규 바이너리): iced 0.13 기반 read-only 대시보드. 4 탭 (Containers/Images/Volumes/Networks) 라이브 갱신 — 연결 시 모든 토픽 구독, 이벤트마다 해당 탭의 `*List` 재호출. 데몬 끊김 시 exponential backoff (1s → 30s) 재연결, 빨간 배너로 연결 상태 표시. 순수 상태 reducer (`linpodx_gui::state::App::apply`) 는 단위 테스트 가능.
- 신규 라이브 통합 테스트 `crates/linpodx-daemon/tests/e2e_events.rs` (`#[ignore]` 게이트): 데몬 spawn → `linpodx events --json --topic container` 백그라운드 실행 → CLI 로 컨테이너 라이프사이클 발생 → `created`/`started`/`removed` notification 출력 검증. Podman 5.8.1 으로 로컬 검증 완료.
- 단위 테스트 40 개 (Phase 1A 의 27 → 40): +5 IPC envelope serde (ServerMessage discrimination, Notification roundtrip, EventTopic snake_case, EventTopic::parse 별칭, Subscribe 직렬화), +3 event-bus 필터링, +5 GUI 상태 reducer.
- iced 워크스페이스 의존성 추가 (MIT, `tokio` 피처). 첫 빌드 시간 김 (wgpu / fontdb / smithay 등).

### 추가됨 — Phase 1A (리소스 관리)

- `linpodx-common::state`: 9 개 신규 리소스 타입 (`ImageSummary`, `ImageInspect`, `ImageConfig`, `VolumeSummary`, `VolumeInspect`, `NetworkSummary`, `NetworkInspect`, `PortMapping`, `PortProtocol`) + `VolumeMount`. `#[serde(default)]` + `raw` 필드로 forward compat.
- `linpodx-common::ipc`: 14 개 신규 `Method` 변형 (이미지 / 볼륨 / 네트워크 작업), 9 개 신규 typed 응답 별칭. `CreateOptions` 에 `port_mappings`, `volumes`, `networks` 추가. `IPC_VERSION` 은 1 유지 (additive 변경).
- `linpodx-runtime`: 3 개 신규 모듈 — `image::{list, pull, remove, inspect, tag}`, `volume::{list, create, remove, inspect, prune}`, `network::{list, create, remove, inspect, prune}`. `Podman::create` 가 `--publish`, `--volume`, `--network` 플래그 전달.
- `linpodx-cli`: 3 개 신규 서브커맨드 그룹 — `linpodx images {ls,pull,rm,inspect,tag}`, `linpodx volume {ls,create,rm,inspect,prune}`, `linpodx network {ls,create,rm,inspect,prune}`. `linpodx run` 에 `-p / --publish`, `-v / --volume`, `--network` 추가. 이미지 목록은 사람이 읽기 쉬운 크기 표시.
- 4 개 신규 `#[ignore]` 게이트 라이브 통합 테스트 (`images_lifecycle`, `volumes_lifecycle`, `networks_lifecycle`, `port_mapping`) — disposable scratch root 에서 CLI → daemon → podman 전체 경로 검증.
- 단위 테스트 27 개 (Phase 0 의 14 개 → 27): 포트 매핑 파서 변형, 볼륨 마운트 파서, IPC roundtrip, 이미지/볼륨/네트워크 파서 fixture.

### 추가됨 — Phase 0 (Foundation)

- Cargo 워크스페이스 골격: 6 개 크레이트 (`linpodx-common`, `linpodx-runtime`, `linpodx-sandbox`, `linpodx-daemon`, `linpodx-cli`, `linpodx-gui`), `rust-toolchain.toml` (stable, MSRV 1.85), `deny.toml` 라이선스 화이트리스트, 워크스페이스 deps
- `linpodx-common`: 공유 타입 (`ContainerId`, `ImageId`, `VolumeId`, `NetworkId`), JSON-RPC 2.0 IPC envelope + `Method` 열거형, 컨테이너 상태 타입, SQLite (`sqlx`) 인프라 + 마이그레이션 러너, 버전 상수 (`LINPODX_VERSION`, `IPC_VERSION`)
- `linpodx-runtime`: `tokio::process::Command` 기반 Podman 어댑터 — `list` / `inspect` / `create` / `start` / `stop` / `remove` / `pull` / `logs`. 최소 Podman 버전 검사 (≥ 4.6.0). Podman 버전 차이에 관대한 permissive JSON 파싱.
- `linpodx-daemon`: Unix 소켓 NDJSON 서버, JSON-RPC 디스패치, `--podman-root` / `--podman-runroot` 플래그로 샌드박싱, SIGTERM / SIGINT 시 graceful shutdown, `tracing` 구조화 로깅
- `linpodx-cli`: `clap` derive 서브커맨드 (`ps`, `run`, `start`, `stop`, `rm`, `inspect`, `logs`, `version`), table / JSON 출력 형식, 데몬 미연결 시 actionable 에러
- 통합 테스트 (`#[ignore]` 게이트) — 실제 데몬 spawn + 실제 CLI 로 라이프사이클 검증 (disposable scratch root 의 rootless Podman 사용)
- GitHub Actions CI: lint (fmt + clippy `-D warnings`), test (stable + MSRV 1.85 매트릭스), doc, 일일 보안 감사 (`cargo audit`, `cargo deny check`)

### 추가됨 — Setup

- 프로젝트 비전 및 범위 문서화 (README, 설계 노트)
- GitHub 표준 파일: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (영어 + 한국어), PR / 이슈 템플릿
- MIT License
