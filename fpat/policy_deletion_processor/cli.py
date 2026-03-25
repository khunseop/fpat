#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Policy Deletion Processor CLI (Refactored with Pipeline)

방화벽 정책 삭제 프로세서의 모든 기능을 명령줄에서 실행할 수 있는 통합 인터페이스입니다.
"""

import argparse
import sys
import logging
from pathlib import Path
from typing import List, Optional

# 패키지 경로 추가
current_dir = Path(__file__).parent
parent_dir = current_dir.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from fpat.policy_deletion_processor.core.config_manager import ConfigManager
from fpat.policy_deletion_processor.core.pipeline import Pipeline
from fpat.policy_deletion_processor.utils import ExcelManager, FileManager

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_parser():
    parser = argparse.ArgumentParser(
        description='FPAT 정책 삭제 프로세서 통합 CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
작업 번호 안내 (Task IDs):
  1. Description에서 신청번호 파싱
  2. 정책파일에서 신청번호 추출
  3. 정책파일에서 MIS ID 추가
  4. GSAMS 신청정보 가공
  5. 정책파일에 신청정보 추가
  6. 팔로알토 정책 예외처리
  7. 시큐아이 정책 예외처리
  8. 중복정책 공지/삭제 분류
  9. 중복정책 결과를 정책 파일에 추가
  10. 두 개의 미사용 정보 합치기 (Pri, Sec)
  11. 미사용 정보를 정책 파일에 추가
  12. 미사용 예외 정보를 정책 파일에 업데이트
  13. 정리대상 별 공지파일 분류
  14. 신청정보에서 자동연장 점검

사용 예제:
  # 단일 작업 비대화형 실행
  python -m fpat.policy_deletion_processor.cli --task 1 --files policy.xlsx
  
  # 여러 작업 순차 실행 (파이프라인)
  python -m fpat.policy_deletion_processor.cli --task 1 2 5 --files policy.xlsx info.xlsx
"""
    )
    
    parser.add_argument('--task', '-t', type=int, nargs='+', required=True, help='실행할 작업 번호 리스트 (1-14)')
    parser.add_argument('--files', '-f', nargs='+', help='작업에 사용할 파일 경로 리스트 (순서대로 입력)')
    parser.add_argument('--config', '-c', type=str, help='설정 파일(fpat.yaml) 경로')
    parser.add_argument('--verbose', '-v', action='store_true', help='상세 로그 출력')
    
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 설정 및 관리자 초기화
    config = ConfigManager(args.config)
    file_manager = FileManager(config)
    excel_manager = ExcelManager(config)
    
    # 비대화형 모드를 위해 파일 리스트 주입
    if args.files:
        file_manager.set_forced_files(args.files)
    
    # 파이프라인 생성 및 단계 추가
    pipeline = Pipeline(config, file_manager, excel_manager)
    for task_id in args.task:
        pipeline.add_step(task_id)
    
    # 실행
    if pipeline.run():
        logger.info("모든 작업이 성공적으로 완료되었습니다.")
        sys.exit(0)
    else:
        logger.error("작업 실행 중 오류가 발생했습니다.")
        sys.exit(1)

if __name__ == '__main__':
    main()
