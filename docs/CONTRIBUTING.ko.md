# linpodx 기여 가이드

[English](../CONTRIBUTING.md) | **한국어**

linpodx에 기여해 주셔서 감사합니다.

## 개발 환경 준비

### 사전 요구사항

- Linux (Wayland 또는 X11)
- Podman ≥ 4.6.0 (rootless 권장)
- Rust stable 툴체인 (≥ 1.85). 저장소 루트의 `rust-toolchain.toml` 가 자동으로 stable 을 핀합니다.
- `rustfmt`, `clippy` 컴포넌트 — `rust-toolchain.toml` 가 자동으로 요청
- GUI 개발 시: `linpodx-gui` 는 시스템 WebKitGTK 4.1 + GTK 3 을 동적 링크하는 Tauri 2 셸입니다 — 빌드 의존성은 Debian/Ubuntu `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev`, Fedora `webkit2gtk4.1-devel`, openSUSE Tumbleweed `webkitgtk3-devel`

### 빌드

```bash
git clone https://github.com/kernalix7/linpodx.git
cd linpodx
cargo build --workspace
```

### 테스트

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## 작업 흐름

1. 저장소를 Fork 합니다
2. 기능 브랜치를 생성합니다: `git checkout -b feat/my-change`
3. Conventional Commits 스타일로 커밋합니다 (아래 참조)
4. Push 후 Pull Request를 생성합니다

## Pull Request 체크리스트

- [ ] 변경 범위와 목적이 명확한가?
- [ ] 필요한 테스트를 추가/갱신했는가?
- [ ] `cargo build --workspace` 통과하는가?
- [ ] `cargo fmt --all -- --check` 통과하는가?
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` 통과하는가?
- [ ] `cargo test --workspace` 통과하는가?
- [ ] 동작 변경 시 README/문서를 갱신했는가? (해당 시 한국어/영어 모두)

## 버전 및 릴리스

linpodx는 Cargo 호환 SemVer와 깔끔한 버전 태그를 사용합니다.
`Cargo.toml` 이 버전의 source of truth 입니다.

- `vX.Y.Z` 는 공개 버전 태그입니다.
- `REL-vX.Y.Z` 는 `.github/workflows/release.yml` 을 실행하는 릴리스 marker 태그입니다.
- 프리릴리스는 `v0.2.0-rc.1`, `REL-v0.2.0-rc.1` 처럼 Cargo SemVer suffix 를 사용합니다.
- RTM suffix 나 4단계 버전은 사용하지 않습니다.

릴리스에는 같은 커밋을 가리키는 두 태그가 모두 필요합니다.

```bash
git tag -a vX.Y.Z -m "linpodx vX.Y.Z"
git tag -a REL-vX.Y.Z vX.Y.Z^{} -m "release linpodx vX.Y.Z"
git push origin vX.Y.Z REL-vX.Y.Z
```

릴리스 워크플로는 태그 버전과 `Cargo.toml` 버전 일치 여부를 확인하고,
workspace 검증을 수행한 뒤, `CHANGELOG.md` 의 해당 버전 섹션을 GitHub Release
본문으로 사용합니다.

전체 버전 정책과 릴리스 체크리스트는 [docs/RELEASE.md](RELEASE.md)를 봅니다.

## 릴리스 노트 작성

`CHANGELOG.md` 와 `docs/CHANGELOG.ko.md` 의 각 버전 섹션은 `### Highlights` 로
시작합니다. GitHub Release 본문은 해당 섹션을 그대로 사용하므로, 사용자가 가장
먼저 볼 내용이 Highlights 입니다.

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Highlights

**한 문장 headline.** 필요하면 1-2 문장 설명을 덧붙입니다.

- 가장 중요한 사용자 가시 변경
- 두 번째로 중요한 변경
- 세 번째 변경

### Added
### Changed
### Fixed
```

## 커밋 메시지 규칙

[Conventional Commits](https://www.conventionalcommits.org/)를 사용합니다.
- `feat:` 새 기능
- `fix:` 버그 수정
- `docs:` 문서 변경
- `refactor:` 동작 변경 없는 구조 개선
- `test:` 테스트 변경
- `chore:` 유지보수 작업
- `perf:` 성능 개선
- `build:` 빌드 시스템 변경
- `ci:` CI / 워크플로 변경

## 보안

보안 이슈는 [SECURITY.ko.md](SECURITY.ko.md)의 제보 절차를 따라 주세요.
