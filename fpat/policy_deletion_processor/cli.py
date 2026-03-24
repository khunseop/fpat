#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Policy Deletion Processor CLI (Full Version)

방화벽 정책 삭제 프로세서의 모든 기능을 명령줄에서 실행할 수 있는 통합 인터페이스입니다.
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from typing import List, Optional

# 패키지 경로 추가
current_dir = Path(__file__).parent
parent_dir = current_dir.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from fpat.policy_deletion_processor.core.config_manager import ConfigManager
from fpat.policy_deletion_processor.processors import (
    RequestParser, RequestExtractor, MisIdAdder, ApplicationAggregator,
    RequestInfoAdder, ExceptionHandler, DuplicatePolicyClassifier,
    MergeHitcount, PolicyUsageProcessor, NotificationClassifier,
    AutoRenewalChecker
)
from fpat.policy_deletion_processor.utils import ExcelManager, FileManager

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PolicyDeletionProcessorCLI:
    def __init__(self, config_path: Optional[str] = None):
        self.config = ConfigManager(config_path)
        self.file_manager = FileManager(self.config)
        self.excel_manager = ExcelManager(self.config)
        
        # 프로세서들 초기화
        self.processors = {
            1: RequestParser(self.config).parse_request_type,
            2: RequestExtractor(self.config).extract_request_id,
            3: MisIdAdder(self.config).add_mis_id,
            4: ApplicationAggregator(self.config).collect_applications,
            5: RequestInfoAdder(self.config).add_request_info,
            6: ExceptionHandler(self.config).paloalto_exception,
            7: ExceptionHandler(self.config).secui_exception,
            8: DuplicatePolicyClassifier(self.config).organize_redundant_file,
            9: DuplicatePolicyClassifier(self.config).add_duplicate_status,
            10: MergeHitcount(self.config).mergehitcounts,
            11: PolicyUsageProcessor(self.config).add_usage_status,
            12: PolicyUsageProcessor(self.config).update_excepted_usage,
            13: NotificationClassifier(self.config).classify_notifications,
            14: AutoRenewalChecker(self.config).renewal_check
        }

    def execute_task(self, task_id: int, files: List[str]) -> bool:
        """지정된 태스크를 실행합니다."""
        if task_id not in self.processors:
            logger.error(f"유효하지 않은 작업 번호입니다: {task_id}")
            return False

        # 비대화형 모드를 위해 FileManager에 파일 리스트 주입
        if files:
            self.file_manager.set_forced_files(files)
            logger.info(f"작업 {task_id} 실행 (입력 파일: {', '.join(files)})")
        else:
            logger.info(f"작업 {task_id} 실행 (대화형 모드)")

        processor_func = self.processors[task_id]
        
        try:
            # 특수한 인자를 받는 경우 처리
            if task_id == 13: # classify_notifications
                return processor_func(self.file_manager, self.excel_manager)
            else:
                return processor_func(self.file_manager)
        except Exception as e:
            logger.exception(f"작업 {task_id} 실행 중 오류 발생: {e}")
            return False

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
  # 1번 작업 (파싱) 비대화형 실행
  python -m fpat.policy_deletion_processor.cli --task 1 --files policy.xlsx
  
  # 5번 작업 (정보 추가) 비대화형 실행 (파일 2개 필요)
  python -m fpat.policy_deletion_processor.cli --task 5 --files policy.xlsx info.xlsx
  
  # 8번 작업 (중복 분류) 대화형 실행
  python -m fpat.policy_deletion_processor.cli --task 8
"""
    )
    
    parser.add_argument('--task', '-t', type=int, required=True, help='실행할 작업 번호 (1-14)')
    parser.add_argument('--files', '-f', nargs='+', help='작업에 사용할 파일 경로 리스트 (순서대로 입력)')
    parser.add_argument('--config', '-c', type=str, help='설정 파일(fpat.yaml) 경로')
    parser.add_argument('--verbose', '-v', action='store_true', help='상세 로그 출력')
    
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    cli = PolicyDeletionProcessorCLI(config_path=args.config)
    
    success = cli.execute_task(args.task, args.files or [])
    
    if success:
        logger.info("작업이 성공적으로 완료되었습니다.")
        sys.exit(0)
    else:
        logger.error("작업 실행 중 오류가 발생했습니다.")
        sys.exit(1)

if __name__ == '__main__':
    main()
