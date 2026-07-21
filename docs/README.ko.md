# linpodx

[English](../README.md) | **한국어**

리눅스 네이티브 컨테이너 관리 플랫폼. CLI와 GUI로 컨테이너를 다루고, AI 에이전트를 격리된 환경에서 안전하게 실행하며, 컨테이너 안의 GUI 애플리케이션을 호스트 데스크톱과 자연스럽게 통합하는 것을 목표로 합니다.

```bash
# 최신 stable 릴리스
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash

# main HEAD 개발 버전
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/install.sh | bash -s -- --main

# 삭제 (데이터는 보존, --purge 사용 시 data/config 삭제)
curl -fsSL https://raw.githubusercontent.com/kernalix7/linpodx/main/uninstall.sh | bash -s -- --confirm
```

> **상태 (v0.1.0 pre-alpha, 2026-05-13):** Phase 0..17 구현이 저장소에 포함되어 있습니다. 컨테이너 / 이미지 / 볼륨 / 네트워크 CRUD, 데몬 이벤트 버스, Tauri 기반 데스크톱 GUI, YAML 샌드박스 정책, 승인 게이트, 스냅샷, 세션 타임라인, host-stdio 브리지, GUI 패스스루, 멀티 디스트로 템플릿, 원격 데몬, 플러그인, 클러스터 기반, 스냅샷 암호화까지 포함합니다. `cargo test --workspace` 기준 829 passed / 0 failed / 54 ignored 입니다.

---

## 왜 linpodx인가

기존 도구들의 빈 자리를 메우는 것을 목표로 합니다.

| 도구 | 한계 |
|---|---|
| Docker Desktop | 무겁고, 상업적 사용에 라이선스 제약, GUI 통합 빈약, AI 샌드박스 개념 없음 |
| Rancher Desktop | Kubernetes 중심, 데일리 컨테이너 관리에는 과함 |
| Podman Desktop | 일반 컨테이너 관리에는 좋지만 AI 에이전트 / 데스크톱 통합 시나리오 없음 |
| distrobox / toolbx | 멀티 배포판은 잘 되지만 CLI 중심, GUI / 보안 프로필 부족 |
| 풀 VM (GNOME Boxes 등) | 자원 사용량 큼, 부팅 느림 |

`linpodx`는 **데스크톱급 컨테이너 매니저** + **AI 에이전트 안전 실행 환경** + **GUI 통합 멀티-배포판 환경**을 하나로 묶어 제공합니다.

---

## 대표 사용 사례

### 1. AI 에이전트 샌드박스
셸 명령을 실행하는 자동화 에이전트를 컨테이너 내부에서 실행. 호스트 파일시스템·시스템 설정에 영향을 주지 않아 *"매번 사람이 승인 vs 완전 자동"*의 중간 지점을 제공합니다. 작업 디렉터리를 마운트하고, 정책에 따라 네트워크와 권한을 제한하며, 세션을 스냅샷으로 보존/롤백할 수 있습니다.

### 2. 데스크톱 컨테이너 매니저
GUI와 CLI를 모두 제공해 컨테이너 라이프사이클·이미지·볼륨·네트워크를 손쉽게 관리합니다. Docker Desktop이 커버하는 일상 워크플로의 리눅스 네이티브 대안입니다.

### 3. 경량 멀티-배포판 환경
Ubuntu, Fedora, Arch, Debian, Alpine, NixOS 등을 컨테이너로 띄워 풀 VM 없이 다양한 환경에서 작업합니다. 컨테이너 내부에서 `systemd`도 동작하도록 지원합니다.

### 4. GUI 통합 컨테이너
컨테이너 내부의 그래픽 애플리케이션을 호스트 데스크톱에 자연스럽게 표시 (Wayland/X11, 오디오, 클립보드, 파일 드래그앤드롭, GPU 가속). 데스크톱 항목으로 자동 등록되어 일반 앱처럼 실행됩니다.

### 5. 격리된 데일리 드라이버 / 보안
브라우저, 메신저, 작업 도구 등을 컨테이너에 격리해 메인 OS는 깨끗하게 유지. 민감한 작업용 컨테이너 / 신뢰 낮은 소프트웨어용 컨테이너를 분리 운용합니다.

---

## 핵심 기능 (Must-have, MVP)

### 컨테이너 라이프사이클
- 생성 / 시작 / 정지 / 재시작 / 일시정지 / 삭제
- 컨테이너 내부 셸 진입 (`exec`)
- 로그 / 프로세스 / 리소스 사용량 조회
- 라벨 / 태그 / 그룹 단위 관리

### 이미지 관리
- 레지스트리에서 풀 / 빌드 / 태그 / 푸시 / 삭제
- OCI 이미지 표준 준수
- 로컬 이미지 검색 및 정리 (GC)
- Containerfile / Dockerfile 빌드 지원

### 볼륨 / 스토리지
- 명명 볼륨 / 바인드 마운트
- 스냅샷 및 클로닝 (BTRFS / ZFS / overlayfs)
- 볼륨 백업·복원·내보내기

### 네트워킹
- 브리지 / 호스트 / 사용자 정의 네트워크
- 포트 매핑 및 방화벽 규칙
- 컨테이너별 DNS, egress 정책
- 네임스페이스 기반 격리

### 보안 기본값
- Rootless 실행 (user namespace remapping)
- Seccomp / AppArmor / SELinux 프로필 적용
- Capability 드롭, read-only rootfs 옵션
- 시크릿 관리 (환경 변수로 토큰 노출 방지)

### CLI
- 직관적인 서브커맨드 (`linpodx run`, `linpodx ps`, `linpodx sandbox …`)
- Bash / Zsh / Fish 보완 스크립트
- 출력 포맷 선택 (table / JSON / YAML)
- 파이프 친화적 디자인

### GUI (데스크톱 앱)
- 컨테이너·이미지·볼륨·네트워크 대시보드
- 한 번에 보이는 상태/리소스 모니터 (CPU·RAM·Disk·Network)
- 인앱 로그 뷰어 / 인앱 터미널
- 원클릭 액션 (시작·정지·셸·재시작·삭제)
- 라이트/다크 테마

### AI 에이전트 샌드박스
- 사전 정의된 프로필과 사용자 정의 YAML 정책
- 작업 디렉터리 자동 마운트 (호스트 → 컨테이너 워크스페이스)
- 네트워크 정책 (오프라인 / allowlist 도메인 / 풀 네트워크)
- 리소스 한도 (CPU·RAM·Disk·실행 시간)
- 명령 감사 로그 — 컨테이너 안에서 실행된 모든 명령 기록
- 스냅샷 → 실행 → (선택적) 롤백 워크플로
- 호스트의 에이전트가 컨테이너 안 셸을 호출할 수 있는 브리지 (소켓/SSH)

### 멀티-배포판 템플릿
- 주요 배포판 사전 구성 템플릿
- 영구 홈 디렉터리 옵션
- "VM처럼 부팅" 모드 vs "한 번 쓰고 버리는" 모드
- 컨테이너 내부 systemd 지원

### GUI 통합 (Display Passthrough)
- Wayland / X11 소켓 포워딩
- PipeWire / PulseAudio 오디오 패스스루
- GPU 가속 (DRI / NVIDIA)
- 클립보드 공유
- 파일 드래그앤드롭
- HiDPI / 폰트 / 테마 상속
- 호스트 앱 메뉴에 컨테이너 앱 자동 등록

---

## 추가 기능 (Nice-to-have, 점진적 확장)

### 선언형 구성
- `linpodx.yaml` — 컨테이너·볼륨·네트워크·샌드박스 프로필을 한 파일로 정의
- 컨테이너 그룹 / 팟 (서로 의존하는 컨테이너 묶음)
- 구성 변경 시 Hot reload

### 자동화 / API
- REST API + Unix 소켓
- 라이프사이클 훅 (pre-start / post-start / pre-stop / post-stop)
- 파일 변경 감지 → 자동 재시작 (watch mode)
- systemd unit 자동 생성 (부팅 시 자동 실행)

### 관측성 (Observability)
- 컨테이너 통합 로그 집계 / 검색
- 메트릭 대시보드 (Prometheus exporter)
- 시스템 전체 감사 로그
- 이벤트 스트림 (생성·시작·정지·정책 위반 등)

### AI 에이전트 심화
- **Approval gates** — 정해진 카테고리 명령(예: 호스트 디렉터리 쓰기)에 한해서만 사람 승인 요청
- **Diff preview** — 컨테이너에서 호스트로 변경 적용 전 diff 미리보기
- **세션 녹화·재생** — 에이전트가 한 작업의 셸 히스토리·파일 변경을 저장하고 재생
- **MCP 서버 브리지** — Model Context Protocol 서버를 샌드박스 안에서 호스팅
- **정책 기반 도구 호출 차단** — 파일 패턴·도메인·명령어 단위 정책

### 개발자 경험
- VS Code / JetBrains의 dev container 통합
- Compose v2 호환 import
- Docker / Podman에서 컨테이너 import
- 컨테이너 → OCI 이미지 export

### 성능 / 효율
- 이미지 레이어 중복 제거
- Lazy pulling
- 메모리 ballooning / 압축
- I/O / CPU / Network QoS

### 마이그레이션 / 이식성
- 다른 호스트로 컨테이너 마이그레이션 (over SSH)
- 백업 자동화 / 스케줄

### 플러그인 / 확장
- 사용자 정의 스토리지 / 네트워크 드라이버
- 커스텀 보안 프로필
- Hook 스크립트 등록

---

## 계획 중인 아키텍처

```
+-----------------------------------------------+
|  GUI (데스크톱 앱)        CLI (linpodx)       |
+-----------------------------------------------+
|         linpodx daemon / API server           |
|  - 라이프사이클 오케스트레이션               |
|  - 샌드박스 정책 엔진                        |
|  - GUI 패스스루 매니저                       |
|  - 감사 로그 / 이벤트 버스                   |
+-----------------------------------------------+
|  Container runtime: Podman (rootless, OCI)    |
|  Storage: overlayfs / BTRFS / ZFS             |
|  Network: netavark / CNI                      |
|  Display: Wayland · X11 소켓 / PipeWire       |
|  Security: user-namespaces · seccomp ·        |
|            AppArmor / SELinux · capabilities  |
+-----------------------------------------------+
|                 Linux 커널                    |
+-----------------------------------------------+
```

기술 스택:
- 런타임: **Podman** (rootless, daemonless, OCI 표준 — 프로젝트 이름의 "pod"가 여기서 옴)
- 구현 언어: **Rust** (edition 2021, MSRV 1.85)
- 데몬 / API: Rust + `tokio` (멀티 스레드), JSON-RPC 2.0 over Unix socket (NDJSON)
- 로컬 상태: SQLite (`sqlx` async, Public Domain)
- CLI: 동일 워크스페이스의 단일 바이너리, `clap` derive
- GUI: **Tauri 2** 데스크톱 셸(시스템 WebKitGTK 4.1 동적 링크) + 데몬이 서빙하는 **Leptos** 웹 UI — 브라우저와 데스크톱이 코드베이스를 공유, 전 구간 MIT/Apache 라이선스

---

## 로드맵 (예정)

| Phase | 목표 |
|---|---|
| **0. 기반** | Podman 래핑, CLI 골격, 기본 컨테이너 CRUD |
| **1. MVP** | GUI 대시보드, 이미지·볼륨·네트워크 관리, 기본 샌드박스 프로필 |
| **2. AI 샌드박스** | Approval gate, 감사 로그, 스냅샷 롤백, MCP 브리지 |
| **3. GUI 통합** | Wayland·X11·오디오·GPU 패스스루, 데스크톱 앱 메뉴 통합 |
| **4. 멀티-배포판** | 배포판 템플릿 카탈로그, systemd 컨테이너, "VM 모드" |
| **5. 자동화** | REST API, 선언형 `linpodx.yaml`, systemd unit 생성 |
| **6. 생태계** | 플러그인 시스템, 마이그레이션, 관측성 통합 |

---

## 비범위 (Non-goals)

다음은 의도적으로 범위에 포함하지 않습니다.

- **Kubernetes 오케스트레이션** — Rancher / k3s / k0s가 잘 다루는 영역.
- **Windows / macOS 1차 지원** — Linux 네이티브 환경에 집중. (WSL2 / VM 우회 사용은 별도 검토.)
- **클라우드 멀티-호스트 클러스터링** — 단일 데스크톱·워크스테이션 환경 우선.
- **상용 라이선스 게이팅** — 핵심 기능에 라이선스 제약을 두지 않음.

---

## 라이선스

[MIT License](../LICENSE).

## 기여

설계 단계라 외부 기여 가이드는 아직 준비되지 않았습니다. 이슈로 사용 사례·아이디어·우려를 공유해 주세요.
