# 📋 FPAT 프로젝트 개선 및 미구현 작업 리스트 (TODO)

본 문서는 FPAT 라이브러리의 완성도를 높이기 위해 식별된 미구현 기능, 오류 수정, 아키텍처 개선 사항을 관리합니다.

---

## 🚨 우선순위: 상 (즉시 수정 필요)

### 1. 오류 및 예외 처리 강화
- [x] **`paloalto_parameter_checker`**: `ssh_checker.py`, `report.py` 내의 `except Exception: pass` 구문을 적절한 로깅(`logger.error`) 및 예외 처리로 교체. (연결 누수 및 디버깅 방해 요소 제거)
- [x] **`firewall_module/ngf`**: `NGFClient`가 에러 발생 시 `None`을 반환하는 대신 구체적인 커스텀 Exception을 발생시키도록 수정.
- [x] **파일명 정규화**: `fpat/policy_deletion_processor/processors/하단최신정책검증.py`를 영문명(예: `bottom_latest_policy_validator.py`)으로 변경하고 관련 임포트 경로 수정.

### 2. 핵심 미구현 기능 구현
- [ ] **`firewall_analyzer`**: `fpat/firewall_analyzer/core/policy_analyzer.py`의 `analyze_usage()` (사용현황 분석) 로직 구현. (현재 `pass` 처리됨)

---

## 📂 우선순위: 중 (기능 완성도 및 구조 개선)

### 1. 방화벽 모듈(Vendor) 고도화
- [x] **`MF2Collector`**:
    - [x] `export_usage_logs()`, `export_service_group_objects()` 메서드의 실제 구현 검토 및 미지원 경고 로깅 추가 완료.
    - [x] 로컬 `temp/` 파일 다운로드 방식에서 메모리/스트림 기반 파싱으로 전환 완료.
- [ ] **`NGFCollector`**: `get_system_info()` 연동. (현재 타 벤더도 미지원 상태이므로 추후 공통 스펙 확정 시 진행)
- [x] **하드코딩 제거**: `NGFClient`의 로그인 타임아웃(3s), `User-Agent` 등을 설정값(config)으로 관리하도록 분리 완료.

### 2. 아키텍처 리팩토링
- [ ] **`FirewallCollectorFactory`**: `username/password` 외에 `client_id/secret` 등 벤더별 다양한 인증 파라미터를 유연하게 수용할 수 있도록 매개변수 구조 개선 (`**kwargs` 등 활용).
- [x] **`policy_deletion_processor`**: 평면적인 `processors/` 구조를 파이프라인(Pipeline) 패턴으로 정형화하여 확장성 확보 완료. (BaseProcessor 및 Pipeline 엔진 도입)

---

## ⚙️ 우선순위: 하 (유지보수 및 편의성)

### 1. 안정성 및 테스트
- [ ] **`policy_comparator`**: 빈 DataFrame(MF2 등) 처리 시 병합 오류 방지를 위한 데이터 검증 로직 추가.
- [ ] **전체 모듈**: 주요 로직에 대한 단위 테스트(Unit Test) 코드 보강.
- [ ] **Type Hinting**: 모든 공개 API 메서드에 타입 힌트가 누락된 부분이 없는지 전수 점검.

---

## ✅ 완료된 항목
- [x] 프로젝트 전체 구조 분석 및 1차 버그 수정 (오타, 변수명 등)
- [x] 각 모듈별 README.md 문서화 작업
- [x] 중앙 집중형 TODO 리스트 작성
