# FPAT (Firewall Policy Analysis Tool)

방화벽 정책 분석 및 관리를 위한 통합 Python 라이브러리이자 CLI 도구입니다. 데이터 추출부터 분석, 삭제 프로세스까지 전 과정을 자동화할 수 있도록 설계되었습니다.

## 🚀 주요 기능

- **통합 CLI**: `python -m fpat` 또는 `fpat.exe` 단일 명령어로 추출, 분석, 삭제 프로세스 통합 실행.
- **다중 벤더 지원**: PaloAlto, SECUI NGF, MF2 등 다양한 방화벽 연동.
- **현대적인 설정 관리**: 주석과 기간제 예외 처리를 지원하는 YAML 기반 설정 시스템.
- **정책 분석**: 중복 정책, Shadow 정책 탐지 및 IP/CIDR 기반 정밀 필터링.
- **보안 감사**: PaloAlto 보안 파라미터 자동 점검 웹 UI 제공.

## 📦 설치 및 빌드

### 1. 라이브러리 설치
```bash
pip install git+https://github.com/khunseop/fpat.git
```

### 2. 단일 EXE 파일 빌드
프로젝트의 모든 기능을 포함하는 단일 실행 파일(`.exe`)을 생성할 수 있습니다.

```bash
python build_exe.py
```
빌드 완료 후 `dist/fpat` (Windows의 경우 `fpat.exe`) 파일이 생성됩니다.

---

## 🔧 통합 CLI 사용법

FPAT은 모든 기능을 통합 CLI(`python -m fpat` 또는 빌드된 `fpat.exe`)를 통해 제공합니다.

### 1. 방화벽 데이터 추출 (`extract`)
```bash
fpat extract --vendor paloalto --hostname 1.1.1.1 --username admin --export-type all --output raw.xlsx
```

### 2. 정책 분석 (`analyze`)
```bash
fpat analyze --input raw.xlsx --vendor paloalto --type all
```

### 3. 정책 삭제 프로세스 처리 (`process`)
```bash
fpat process --task 1 2 5 --files raw.xlsx
```

### 4. 파라미터 체크 웹 UI 실행 (`checker`)
```bash
fpat checker --port 5000
```

---

## ⚙️ 설정 관리 (`fpat.yaml`)

FPAT은 프로젝트 루트의 `fpat.yaml` 파일을 통해 동작을 제어합니다.

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
