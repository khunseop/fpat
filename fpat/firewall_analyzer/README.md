# Firewall Analyzer Module

정책 분석 및 필터링을 위한 핵심 모듈입니다. 방화벽 정책의 중복성, Shadow 정책, 그리고 IP/CIDR 기반의 정밀 필터링 기능을 제공합니다.

## 🚀 주요 기능

- **중복 정책 분석 (Redundancy Analysis)**: 동일하거나 포함 관계에 있는 정책을 식별하여 최적화 포인트를 찾아냅니다.
- **Shadow 정책 분석 (Shadow Analysis)**: 상위 정책에 의해 가려져 실행되지 않는 정책을 탐지합니다.
- **정밀 정책 필터링 (Policy Filtering)**: 
  - IP 주소, CIDR, IP 범위 기반 검색
  - Source/Destination/Both 필터링 지원
  - 복합 조건(AND/OR) 검색 및 Any 포함 여부 설정
- **정책 해석 (Policy Resolver)**: 복잡한 객체와 서비스를 실제 값으로 해석하여 분석에 활용합니다.

## 📂 디렉토리 구조

```text
firewall_analyzer/
├── core/
│   ├── change_analyzer.py      # 정책 변경 사항 분석
│   ├── policy_analyzer.py      # 기본 정책 분석 엔진
│   ├── policy_filter.py        # IP/CIDR 기반 필터링 로직
│   ├── policy_resolver.py      # 객체 및 서비스 해석기
│   ├── redundancy_analyzer.py  # 중복 정책 탐지
│   └── shadow_analyzer.py      # Shadow 정책 탐지
└── utils/
    └── excel_handler.py        # 분석 결과 Excel 저장 및 로드
```

## 🔧 사용법

### 1. 통합 CLI (권장)
추출된 엑셀 파일을 분석하여 중복 및 Shadow 정책 리포트를 생성합니다.

```bash
# 전체 분석 (중복 & Shadow)
python -m fpat analyze --input raw_data.xlsx --vendor paloalto --type all
```

### 2. 프로그래밍 방식 사용 (API)
...
## 📋 의존성

- **pandas**: 데이터 프레임 처리
- **ipaddress**: IP 주소 수학적 포함 관계 분석 (표준 라이브러리)
- **openpyxl**: Excel 파일 핸들링
