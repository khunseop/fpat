# Policy Comparator Module

두 시점의 방화벽 정책 및 객체 데이터를 비교하여 변경사항(추가, 삭제, 수정)을 분석하는 모듈입니다. 보안 감사 및 정책 정합성 검증에 최적화되어 있습니다.

## 🚀 주요 기능

- **객체 비교 (Object Comparison)**: 주소 객체, 서비스 객체, 그룹 객체의 변경 사항을 상세하게 추적합니다.
- **정책 비교 (Policy Comparison)**: 보안 규칙의 순서 변경, 필드 수정, 신규 추가 및 삭제 항목을 식별합니다.
- **Excel 리포트 생성**: 비교 결과를 시각적으로 확인하기 쉬운 포맷의 Excel 파일로 출력합니다.
- **대용량 데이터 지원**: 최적화된 비교 알고리즘을 통해 수만 개의 정책도 효율적으로 처리합니다.

## 📂 디렉토리 구조

```text
policy_comparator/
├── comparator.py       # 핵심 비교 로직 (PolicyComparator 클래스)
├── excel_formatter.py  # 비교 결과 Excel 서식 적용 및 저장
└── utils.py            # 비교를 위한 유틸리티 함수
```

## 🔧 사용법

### 1. 정책 및 객체 비교

```python
from fpat.policy_comparator import PolicyComparator

# 비교 인스턴스 생성
comparator = PolicyComparator(
    policy_old="old_policy.xlsx",
    policy_new="new_policy.xlsx", 
    object_old="old_objects.xlsx",
    object_new="new_objects.xlsx"
)

# 모든 객체(주소, 서비스, 그룹) 비교 실행
comparator.compare_all_objects()

# 보안 정책(Security Rules) 비교 실행
comparator.compare_policies()

# 결과를 Excel 파일로 저장
comparator.export_to_excel("comparison_report.xlsx")
```

## 📋 주요 클래스

### `PolicyComparator`
- `compare_address_objects()`: 주소 객체 비교
- `compare_service_objects()`: 서비스 객체 비교
- `compare_group_objects()`: 그룹 객체 비교
- `compare_policies()`: 보안 규칙 비교
