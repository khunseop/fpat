# Policy Deletion Processor

방화벽 정책 삭제 시나리오를 처리하고 분석하는 모듈입니다.

## 주요 기능

- 정책 삭제 영향도 분석
- 삭제 시나리오 처리
- 관련 정책 및 객체 의존성 분석
- 신청 정보 파싱 및 추출
- 미사용 정책 분석

## CLI 사용법

### 기본 사용법

```bash
# 모든 프로세서를 순차적으로 실행
python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --run-all

# 신청 정보 파싱만 실행
python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --parse-request

# 신청 ID 추출만 실행
python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --extract-request-id

# 미사용 정보 추가
python -m fpat.policy_deletion_processor.cli \
    --policy-file policy.xlsx \
    --usage-file usage.xlsx \
    --add-usage-status
```

### 옵션 설명

- `--policy-file`, `-p`: 정책 파일 경로 (필수)
- `--output-file`, `-o`: 출력 파일 경로 (선택사항, 지정하지 않으면 자동 생성)
- `--output-dir`, `-d`: 출력 디렉토리 (선택사항)
- `--config-file`, `-c`: 설정 파일 경로 (선택사항)
- `--usage-file`, `-u`: 미사용 정보 파일 경로 (add-usage-status 옵션 사용 시 필요)
- `--verbose`, `-v`: 상세 로그 출력

### 작업 옵션 (하나만 선택)

- `--run-all`: 모든 프로세서를 순차적으로 실행
- `--parse-request`: 신청 정보 파싱만 실행
- `--extract-request-id`: 신청 ID 추출만 실행
- `--add-usage-status`: 미사용 정보 추가

### 사용 예제

```bash
# 전체 프로세스 실행 (출력 디렉토리 지정)
python -m fpat.policy_deletion_processor.cli \
    --policy-file /path/to/policy.xlsx \
    --output-dir /path/to/output \
    --run-all

# 특정 작업만 실행하고 출력 파일 지정
python -m fpat.policy_deletion_processor.cli \
    --policy-file policy.xlsx \
    --output-file result.xlsx \
    --parse-request

# 미사용 정보 추가 (상세 로그)
python -m fpat.policy_deletion_processor.cli \
    --policy-file policy.xlsx \
    --usage-file usage.xlsx \
    --add-usage-status \
    --verbose
```

## 프로그래밍 방식 사용법

### 개별 모듈 import

```python
from fpat.policy_deletion_processor.core import ConfigManager
from fpat.policy_deletion_processor.processors import (
    RequestParser,
    PolicyUsageProcessor
)
from fpat.policy_deletion_processor.utils import FileManager, ExcelManager

# 설정 관리자 초기화
config = ConfigManager('config.json')

# 파일 관리자 및 프로세서 초기화
file_manager = FileManager(config)
request_parser = RequestParser(config)
policy_usage = PolicyUsageProcessor(config)

# 사용 예제
file_manager.select_files()  # 대화형 파일 선택
request_parser.parse_request_type(file_manager)
```

## 프로세서 목록

1. **RequestParser**: 신청 정보 파싱
2. **RequestExtractor**: 신청 ID 추출
3. **MisIdAdder**: MIS ID 추가
4. **ApplicationAggregator**: 애플리케이션 집계
5. **RequestInfoAdder**: 신청 정보 추가
6. **ExceptionHandler**: 예외 처리
7. **DuplicatePolicyClassifier**: 중복 정책 분류
8. **MergeHitcount**: 히트카운트 병합
9. **PolicyUsageProcessor**: 미사용 정책 처리
10. **NotificationClassifier**: 알림 분류

## 설정 파일

설정 파일(`config.json`)을 사용하여 동작을 커스터마이즈할 수 있습니다.

```json
{
  "file_naming": {
    "policy_version_format": "_v{version}",
    "final_version_suffix": "_vf",
    "request_id_prefix": "request_id_"
  },
  "file_extensions": {
    "excel": ".xlsx"
  },
  "timeframes": {
    "recent_policy_days": 90
  },
  "excel_styles": {
    "header_fill_color": "E0E0E0",
    "history_fill_color": "ccffff"
  },
  "except_list": []
}
```

## 자동화 예제

### Bash 스크립트

```bash
#!/bin/bash

POLICY_FILE="policy.xlsx"
USAGE_FILE="usage.xlsx"
OUTPUT_DIR="./output"

# 전체 프로세스 실행
python -m fpat.policy_deletion_processor.cli \
    --policy-file "$POLICY_FILE" \
    --output-dir "$OUTPUT_DIR" \
    --run-all

# 미사용 정보 추가
python -m fpat.policy_deletion_processor.cli \
    --policy-file "$POLICY_FILE" \
    --usage-file "$USAGE_FILE" \
    --add-usage-status \
    --output-dir "$OUTPUT_DIR"
```

### Python 스크립트

```python
#!/usr/bin/env python
import subprocess
import sys

def run_policy_processor(policy_file, usage_file=None, output_dir=None):
    """정책 프로세서 실행"""
    cmd = [
        sys.executable, '-m', 'fpat.policy_deletion_processor.cli',
        '--policy-file', policy_file,
        '--run-all'
    ]
    
    if output_dir:
        cmd.extend(['--output-dir', output_dir])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"오류 발생: {result.stderr}")
        return False
    
    print(result.stdout)
    
    # 미사용 정보 추가
    if usage_file:
        cmd = [
            sys.executable, '-m', 'fpat.policy_deletion_processor.cli',
            '--policy-file', policy_file,
            '--usage-file', usage_file,
            '--add-usage-status'
        ]
        
        if output_dir:
            cmd.extend(['--output-dir', output_dir])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"미사용 정보 추가 오류: {result.stderr}")
            return False
    
    return True

if __name__ == '__main__':
    run_policy_processor('policy.xlsx', 'usage.xlsx', './output')
```

## 주의사항

- 정책 파일은 Excel 형식(.xlsx)이어야 합니다.
- 파일에 'Rule Name' 컬럼이 필수로 포함되어 있어야 합니다.
- 일부 프로세서는 특정 컬럼이 필요할 수 있습니다 (예: 'Description', '미사용여부').
- 출력 파일이 이미 존재하는 경우 덮어쓰기됩니다.

## 문제 해결

### 파일을 찾을 수 없음
- 파일 경로가 올바른지 확인하세요.
- 절대 경로를 사용하거나 현재 작업 디렉토리를 확인하세요.

### 컬럼이 없음
- Excel 파일에 필요한 컬럼이 있는지 확인하세요.
- `--verbose` 옵션을 사용하여 상세 로그를 확인하세요.

### 권한 오류
- 출력 디렉토리에 쓰기 권한이 있는지 확인하세요.
