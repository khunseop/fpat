# PaloAlto Parameter Checker

PaloAlto 방화벽의 설정값(Parameter)을 보안 표준 가이드라인에 따라 자동으로 점검하고 리포트를 생성하는 독립 도구입니다.

## 🚀 주요 기능

- **SSH 기반 자동 점검**: 방화벽에 직접 접속하여 실시간 설정 정보를 수집합니다.
- **보안 가이드 준수 확인**: 패스워드 정책, 세션 타임아웃, 관리자 접근 제한 등 주요 보안 파라미터를 체크합니다.
- **웹 UI 제공**: Flask 기반의 웹 인터페이스를 통해 점검 실행 및 결과를 대시보드 형태로 확인 가능합니다.
- **상세 리포트 생성**: 점검 항목별 통과/실패 여부와 조치 권고 사항을 포함한 리포트를 제공합니다.

## 📂 디렉토리 구조

```text
paloalto_parameter_checker/
├── app.py              # Flask 웹 애플리케이션 메인
├── ssh_checker.py      # SSH 접속 및 커맨드 실행 엔진
├── parameter_manager.py # 점검 항목 및 기준 관리
├── database.py         # 점검 이력 및 결과 저장 (SQLite)
├── report.py           # 리포트 생성 로직
├── templates/          # 웹 UI 템플릿 (HTML)
└── static/             # 정적 리소스 (JS, CSS)
```

## 🔧 사용법

### 1. 웹 서비스 실행

```bash
cd fpat/paloalto_parameter_checker
python run.py
```
실행 후 브라우저에서 `http://localhost:5000` 접속

### 2. 주요 점검 항목
- **Management Interface**: 접근 제어 설정, HTTPS 사용 여부
- **Authentication**: 패스워드 복잡성, 최소 길이, 실패 시 잠금 정책
- **Session**: 관리자 세션 타임아웃, 로그온 배너 설정
- **System**: NTP 설정, DNS 설정, 불필요한 서비스 활성화 여부

## 📋 요구사항

- **paramiko**: SSH 접속용
- **Flask**: 웹 인터페이스
- **pandas**: 점검 결과 데이터 처리
