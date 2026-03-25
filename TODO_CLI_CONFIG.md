# 📋 CLI 및 컨피그 시스템 개편 로드맵 (TODO)

본 문서는 FPAT의 설정 관리 및 CLI 사용성 개선을 위한 작업 현황을 관리합니다.

---

## 🚨 1단계: 설정 시스템 및 예외 관리 개편 (우선순위: 최상)

### 1.1 YAML 기반 컨피그 도입
- [x] `PyYAML` 라이브러리 의존성 추가 (requirements.txt 반영)
- [x] `fpat.yaml` 표준 포맷 정의 및 샘플 파일 생성
- [x] `ConfigManager` 리팩토링: YAML 로드 및 주석 지원, 경로 탐색 로직 개선

### 1.2 고도화된 예외 관리 로직 구현
- [x] **기간제 예외**: `until` 필드 날짜를 체크하여 자동 만료 처리 로직 추가
- [x] **조건부 예외 확장**: 정규식(Regex) 기반 Rule Name 매칭 지원
- [x] `ExceptionHandler` 수정: 새 YAML 설정을 참조하도록 로직 변경

---

## 📂 2단계: CLI 통합 및 기능 확장 (우선순위: 상)

### 2.1 `policy_deletion_processor/cli.py` 전면 개편
- [x] 14가지 모든 태스크(Task)를 `--task` 인자로 매핑
- [x] 대화형 모드와 비대화형 모드(직접 경로 인자)의 명확한 분리
- [x] `FileManager.select_files()` 리팩토링 (인자가 있을 경우 대화형 스킵)

### 2.2 설정 탐색 및 주입 체계 개선
- [x] 설정 탐색 우선순위 구현 (CLI 인자 > 환경 변수 > 로컬 파일 > 기본값)
- [x] `ConfigManager` 통합 및 라이브러리 상단 노출

---

## ⚙️ 3단계: 통합 워크플로우 엔진 구축 (우선순위: 중)

### 3.1 통합 진입점 개발
- [x] `fpat/__main__.py` 생성: `python -m fpat`으로 통합 실행 지원
- [x] `fpat extract` (firewall_module 연동) 및 `fpat process` (deletion_processor 연동) 명령어 구현

---

## ✅ 완료 기준
- [ ] 설정 파일에 주석을 남길 수 있고, 기간 만료 예외가 자동으로 필터링됨
- [ ] 14가지 모든 프로세스를 명령어 한 줄(Non-interactive)로 실행 가능함
- [ ] 설정 파일 위치가 소스 코드와 분리되어 자유롭게 지정 가능함
