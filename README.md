# FPAT (Firewall Policy Analysis Tool)

방화벽 정책 분석 및 관리를 위한 통합 Python 라이브러리이자 CLI 도구입니다. 데이터 추출부터 분석, 삭제 프로세스까지 전 과정을 자동화할 수 있도록 설계되었습니다.

## 🚀 주요 기능

- **통합 CLI**: `python -m fpat` 단일 명령어로 추출 및 분석 프로세스 통합 실행.
- **다중 벤더 지원**: PaloAlto, SECUI NGF, MF2 등 다양한 방화벽 연동.
- **현대적인 설정 관리**: 주석과 기간제 예외 처리를 지원하는 YAML 기반 설정 시스템.
- **정책 분석**: 중복 정책, Shadow 정책 탐지 및 IP/CIDR 기반 정밀 필터링.
- **삭제 워크플로우**: 신청 정보 매칭 및 미사용 정책 정리 프로세스 지원.

## 📦 설치

```bash
# GitHub에서 직접 설치
pip install git+https://github.com/khunseop/fpat.git
```

## 🔧 통합 CLI 사용법

FPAT은 모든 기능을 통합 CLI(`python -m fpat`)를 통해 제공합니다.

### 1. 방화벽 데이터 추출 (`extract`)
벤더사 API 또는 SSH를 통해 정책 및 객체 데이터를 엑셀로 추출합니다.

```bash
python -m fpat extract --vendor paloalto \
    --hostname 192.168.1.1 \
    --username admin \
    --export-type all \
    --output ./data/raw_policy.xlsx
```

### 2. 정책 삭제 프로세스 처리 (`process`)
추출된 데이터를 바탕으로 14가지 분석 태스크를 실행합니다. `--files` 인자를 사용하여 자동화가 가능합니다.

```bash
# 태스크 1: Description에서 신청번호 파싱
python -m fpat process --task 1 --files raw_policy.xlsx

# 태스크 5: 정책 파일에 신청 정보 매칭 (복수 파일 사용)
python -m fpat process --task 5 --files policy_v1.xlsx application_info.xlsx
```

---

## ⚙️ 설정 관리 (`fpat.yaml`)

FPAT은 프로젝트 루트의 `fpat.yaml` 파일을 통해 동작을 제어합니다. (환경 변수 `FPAT_CONFIG`로 경로 지정 가능)

### 기간제 및 패턴 기반 예외 설정
특정 날짜까지 혹은 특정 패턴의 정책을 분석 대상에서 자동으로 제외할 수 있습니다.

```yaml
exceptions:
  request_ids:
    - id: "PS-2024-0001"
      reason: "임시 유지 정책"
      until: "2025-12-31" # 이 날짜가 지나면 자동으로 예외 해제
  
  policy_rules:
    - pattern: "^MGMT_.*" # 정규식 지원
      reason: "관리용 정책 상시 예외"
```

---

## 📂 모듈 구조

| 모듈명 | 설명 |
| :--- | :--- |
| **firewall_module** | 방화벽 데이터 수집 (PaloAlto, NGF, MF2) |
| **firewall_analyzer** | 정책 중복/Shadow 분석 및 IP 필터링 |
| **policy_deletion_processor** | 정책 삭제 영향도 분석 및 처리 프로세스 |
| **policy_comparator** | 시점 간 정책/객체 변경 사항 비교 |
| **paloalto_parameter_checker** | PaloAlto 보안 설정 자동 점검 도구 |

---

## 👤 작성자 및 라이선스

- **작성자**: Hoon (khunseop@gmail.com)
- **라이선스**: Proprietary License
