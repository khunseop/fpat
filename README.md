# FPAT (Firewall Policy Analysis Tool)

방화벽 정책 관리를 위한 통합 Python 라이브러리입니다.

## 🔥 주요 개선사항 (v1.2.0)

### 1단계: 기본 안정성 확보 ✅
- **로깅 시스템**: 구조화된 로깅으로 디버깅 및 모니터링 지원
- **예외 처리 강화**: 세분화된 예외 클래스로 정확한 오류 진단
- **입력 검증**: 모든 입력값에 대한 엄격한 검증 로직
- **연결 상태 확인**: 실시간 연결 상태 모니터링

### 성능 최적화 🚀
- **청크 처리**: 대용량 데이터를 메모리 효율적으로 처리
- **재시도 로직**: 지수 백오프를 이용한 스마트 재시도
- **진행률 추적**: 실시간 작업 진행률 모니터링
- **메모리 최적화**: Excel 파일 작성 시 메모리 사용량 최소화

### 사용성 개선 📖
- **상세한 문서화**: API 레퍼런스와 사용 예제
- **타입 힌트**: 모든 함수와 메서드에 타입 힌트 추가
- **진행률 콜백**: 사용자 정의 진행률 표시 지원

## 🚀 주요 기능

- **정책 비교**: 방화벽 정책과 객체의 변경사항을 비교하고 분석
- **다중 벤더 지원**: PaloAlto, NGF, MF2 등 다양한 방화벽 벤더 지원
- **정책 분석**: 중복성, 변경사항, 사용현황, Shadow 정책 분석
- **정책 필터링**: IP 주소, CIDR, 범위 기반 정책 검색
- **삭제 시나리오**: 정책 삭제 영향도 분석 및 처리

## 📦 설치

### GitHub에서 직접 설치
```bash
pip install git+https://github.com/khunseop/fpat.git
```

### 로컬 개발 설치
```bash
git clone https://github.com/khunseop/fpat.git
cd fpat
pip install -e .
```

### PyPI에서 설치 (향후)
```bash
pip install fpat
```

## 🔧 사용법

### 1. 정책 비교

```python
from fpat import PolicyComparator

# 정책 비교 인스턴스 생성
comparator = PolicyComparator(
    policy_old="old_policy.xlsx",
    policy_new="new_policy.xlsx", 
    object_old="old_objects.xlsx",
    object_new="new_objects.xlsx"
)

# 객체 변경사항 비교
comparator.compare_all_objects()

# 정책 변경사항 비교
comparator.compare_policies()
```

### 2. 방화벽 연동

#### CLI 사용 (권장)

```bash
# PaloAlto 정책 추출
python -m fpat.firewall_module.cli \
    --vendor paloalto \
    --hostname 192.168.1.1 \
    --username admin \
    --export-type policy \
    --output policies.xlsx

# 전체 데이터 추출
python -m fpat.firewall_module.cli \
    --vendor paloalto \
    --hostname 192.168.1.1 \
    --username admin \
    --export-type all \
    --output complete_data.xlsx
```

#### 프로그래밍 방식

```python
from fpat import FirewallCollectorFactory

# PaloAlto 방화벽 연결
firewall = FirewallCollectorFactory.get_collector(
    source_type="paloalto",
    hostname="192.168.1.1",
    username="admin",
    password="password"
)

# 정책 데이터 수집
policies = firewall.export_security_rules()
objects = firewall.export_network_objects()
```

또는 `export_policy_to_excel` 함수 사용:

```python
from fpat.firewall_module import export_policy_to_excel

# 정책 추출 및 Excel 저장
output_file = export_policy_to_excel(
    vendor="paloalto",
    hostname="192.168.1.1",
    username="admin",
    password="password",
    export_type="policy",
    output_path="./policies.xlsx"
)
```

### 3. 정책 분석

```python
from fpat.firewall_analyzer import PolicyAnalyzer, RedundancyAnalyzer, ShadowAnalyzer, PolicyFilter
import pandas as pd

# 정책 데이터 로드
df = pd.read_excel("policies.xlsx")

# 중복 정책 분석
redundancy_analyzer = RedundancyAnalyzer()
redundancy_result = redundancy_analyzer.analyze(df, vendor="paloalto")

# Shadow 정책 분석
shadow_analyzer = ShadowAnalyzer()
shadow_result = shadow_analyzer.analyze(df, vendor="paloalto")

# 정책 필터링 (IP 주소 기반)
policy_filter = PolicyFilter()

# Source 주소로 필터링
filtered_policies = policy_filter.filter_by_source(
    df, 
    search_address="192.168.1.0/24",
    include_any=True
)

# Destination 주소로 필터링
filtered_policies = policy_filter.filter_by_destination(
    df,
    search_address="10.0.0.0/8", 
    include_any=False
)

# 복합 조건 필터링
filtered_policies = policy_filter.filter_by_criteria(
    df,
    source_address="192.168.1.0/24",
    destination_address="10.0.0.0/8",
    match_mode="AND",
    include_any=True
)
```

### 4. 모듈별 사용법

```python
# 기본 사용법 (권장)
from fpat.policy_comparator import PolicyComparator
from fpat.firewall_analyzer import (
    PolicyAnalyzer, 
    RedundancyAnalyzer, 
    ShadowAnalyzer, 
    PolicyFilter
)
from fpat.firewall_module import FirewallInterface

# 고급 기능 (개별 import)
from fpat.firewall_module.collector_factory import FirewallCollectorFactory
from fpat.policy_deletion_processor.processors import policy_usage_processor
```

### 5. 정책 필터링 상세 사용법

```python
from fpat.firewall_analyzer import PolicyFilter
import pandas as pd

# PolicyFilter 인스턴스 생성
filter_obj = PolicyFilter()

# 정책 데이터 로드
df = pd.read_excel("firewall_policies.xlsx")

# 1. Source 주소 기반 필터링
# CIDR 검색
source_filtered = filter_obj.filter_by_source(
    df, 
    search_address="192.168.1.0/24",
    include_any=True,      # any 정책 포함 여부
    use_extracted=True     # Extracted Source 컬럼 사용 여부
)

# IP 범위 검색
source_filtered = filter_obj.filter_by_source(
    df, 
    search_address="192.168.1.1-192.168.1.100",
    include_any=False
)

# 단일 IP 검색
source_filtered = filter_obj.filter_by_source(
    df, 
    search_address="192.168.1.100",
    include_any=False
)

# 2. Destination 주소 기반 필터링
dest_filtered = filter_obj.filter_by_destination(
    df,
    search_address="10.0.0.0/8",
    include_any=False
)

# 3. Source 또는 Destination 모두 검색
both_filtered = filter_obj.filter_by_both(
    df,
    search_address="192.168.1.0/24",
    include_any=True
)

# 4. 복합 조건 필터링
# AND 모드: Source와 Destination 모두 만족
and_filtered = filter_obj.filter_by_criteria(
    df,
    source_address="192.168.1.0/24",
    destination_address="10.0.0.0/8", 
    match_mode="AND",
    include_any=True
)

# OR 모드: Source 또는 Destination 중 하나만 만족
or_filtered = filter_obj.filter_by_criteria(
    df,
    source_address="192.168.1.0/24",
    destination_address="10.0.0.0/8",
    match_mode="OR", 
    include_any=False
)

# 5. 필터링 결과 요약
summary = filter_obj.get_filter_summary(
    original_df=df,
    filtered_df=source_filtered,
    search_criteria={
        'search_type': 'source',
        'address': '192.168.1.0/24',
        'include_any': True
    }
)

print(f"총 정책 수: {summary['total_policies']}")
print(f"매치된 정책 수: {summary['matched_policies']}")
print(f"매치 비율: {summary['match_percentage']:.1f}%")
```

### 6. 고급 사용법

```python
# 방화벽 컬렉터 팩토리 사용 (복잡한 의존성)
from fpat.firewall_module.collector_factory import FirewallCollectorFactory

collector = FirewallCollectorFactory.get_collector(
    source_type="paloalto",
    hostname="192.168.1.1", 
    username="admin",
    password="password"
)

# 삭제 시나리오 처리
from fpat.policy_deletion_processor.processors import policy_usage_processor
from fpat.policy_deletion_processor.utils import excel_manager
```

## 📚 모듈 구조

```
fpat/
├── policy_comparator/          # 정책 비교 기능
├── firewall_module/            # 방화벽 연동 기능
├── firewall_analyzer/         # 정책 분석 기능
├── policy_deletion_processor/ # 삭제 시나리오 처리
└── paloalto_parameter_checker/ # Palo Alto 파라미터 체크 도구
```

## 🔧 지원 방화벽

- **PaloAlto Networks**: PAN-OS
- **NGF**: SECUI NGF
- **MF2**: SECUI MF2
- **Mock**: 테스트 및 개발용

## 📋 요구사항

- Python 3.8+
- pandas >= 1.3.0
- openpyxl >= 3.0.0
- requests >= 2.25.0
- lxml >= 4.6.0
- python-dateutil >= 2.8.0
- urllib3 == 1.26.12
- paramiko >= 3.0.0
- scp >= 0.14.0

자세한 의존성 목록은 `requirements.txt` 또는 `pyproject.toml`을 참조하세요.

## 📄 라이선스

Proprietary License - 이 소프트웨어는 독점 라이선스 하에 배포됩니다.

## 👤 작성자

**Hoon**
- Email: khunseop@gmail.com
- GitHub: [@khunseop](https://github.com/khunseop)

## 🆕 변경 사항

### v1.1.0
- **PolicyFilter** 추가: IP 주소, CIDR, 범위 기반 정책 필터링 기능
- **ShadowAnalyzer** 추가: Shadow 정책 분석 기능
- 정책 관리 필터링 기능 강화
- 복합 조건 검색 지원 (AND/OR 모드)
- any 포함 여부 설정 가능

### v1.0.0
- 초기 릴리스
- 정책 비교 기능 추가
- 다중 벤더 방화벽 지원
- 정책 분석 기능 추가

## 📝 참고사항

- 프로젝트의 최신 정보는 [GitHub 저장소](https://github.com/khunseop/fpat)에서 확인할 수 있습니다.
- 버그 리포트나 기능 제안은 [Issues](https://github.com/khunseop/fpat/issues)에 등록해주세요.
- 각 모듈의 상세 문서는 해당 모듈 디렉토리의 README.md 파일을 참조하세요. 