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

### 1. 중복 및 Shadow 정책 분석

```python
from fpat.firewall_analyzer import RedundancyAnalyzer, ShadowAnalyzer
import pandas as pd

# 정책 데이터 로드
df = pd.read_excel("policies.xlsx")

# 중복 정책 분석
red_analyzer = RedundancyAnalyzer()
redundancy_result = red_analyzer.analyze(df, vendor="paloalto")

# Shadow 정책 분석
sha_analyzer = ShadowAnalyzer()
shadow_result = sha_analyzer.analyze(df, vendor="paloalto")
```

### 2. 상세 정책 필터링

```python
from fpat.firewall_analyzer import PolicyFilter

filter_obj = PolicyFilter()

# CIDR 기반 Source 주소 필터링
filtered_df = filter_obj.filter_by_source(
    df, 
    search_address="192.168.1.0/24",
    include_any=True
)

# 복합 조건 필터링 (Source AND Destination)
both_filtered = filter_obj.filter_by_criteria(
    df,
    source_address="192.168.1.0/24",
    destination_address="10.0.0.0/8",
    match_mode="AND"
)
```

## 📋 의존성

- **pandas**: 데이터 프레임 처리
- **netaddr**: IP 주소 및 네트워크 연산
- **openpyxl**: Excel 파일 핸들링
