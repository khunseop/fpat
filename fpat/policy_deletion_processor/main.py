#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
방화벽 정책 관리 프로세스 메인 스크립트
"""

import logging
import sys
import os

def get_base_dir() -> str:
    if getattr(sys, 'frozen', False):   # PyInstaller로 빌드된 경우
        print(os.path.dirname(sys.executable))
        return os.path.dirname(sys.executable)
    else:   # Python 파일로 실행하는 경우
        return os.path.dirname(os.path.abspath(__file__))

# 로그 파일 경로 지정 (EXE 위치 기준)
log_path = os.path.join(get_base_dir(), 'firewall_policy_manager.log')

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 패키지 경로 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_deletion_processor.core.config_manager import ConfigManager
from policy_deletion_processor.utils.file_manager import FileManager
from policy_deletion_processor.utils.excel_manager import ExcelManager
from policy_deletion_processor.processors.request_parser import RequestParser
from policy_deletion_processor.processors.request_extractor import RequestExtractor
from policy_deletion_processor.processors.request_info_adder import RequestInfoAdder
from policy_deletion_processor.processors.mis_id_adder import MisIdAdder
from policy_deletion_processor.processors.exception_handler import ExceptionHandler
from policy_deletion_processor.processors.duplicate_policy_classifier import DuplicatePolicyClassifier
from policy_deletion_processor.processors.policy_usage_processor import PolicyUsageProcessor
from policy_deletion_processor.processors.notification_classifier import NotificationClassifier
from policy_deletion_processor.processors.merge_hitcount import MergeHitcount
from policy_deletion_processor.processors.application_aggregator import ApplicationAggregator
from policy_deletion_processor.processors.auto_renewal_checker import AutoRenewalChecker

def select_task():
    """
    작업을 선택합니다.

    Returns:
        int: 선택된 작업 번호
    """
    print("\n방화벽 정책 관리 프로세스")
    print("=" * 50)
    print("시작할 작업 번호를 입력해주세요.")
    print("1. Description에서 신청번호 파싱하기")
    print("2. 정책파일에서 신청번호 추출하기")
    print("3. 정책파일에서 MIS ID 추가하기")
    print("4. GSAMS에서 받은 신청정보 가공하기")
    print("5. 정책파일에 신청정보 추가하기")
    print("6. 팔로알토 정책에서 예외처리하기")
    print("7. 시큐아이 정책에서 예외처리하기")
    print("8. 중복정책 공지/삭제 분류하기")
    print("9. 중복정책 분류 결과를 정책 파일에 추가하기")
    print("10. 두 개의 미사용 정보를 하나로 합치기(Pri, Sec)")
    print("11. 미사용 정책 정보를 정책 파일에 추가하기")
    print("12. 미사용 예외 정보를 정책 파일에 업데이트하기 (중복정책 미사용 예외 건)")
    print("13. 정리대상 별 공지파일 분류하기")
    print("14. 신청정보에서 자동연장 점검하기")
    print("0. 종료")
    print("=" * 50)

    while True:
        try:
            choice = input("작업번호 (1-14, 종료: 0): ")
            if choice.isdigit():
                choice = int(choice)
                if 0 <= choice <= 14:
                    return choice
            print('유효하지 않은 번호입니다. 다시 시도하세요.')
        except ValueError:
            print("유효하지 않은 입력입니다. 다시 시도하세요.")

def main():
    """
    메인 함수
    """
    try:
        # 설정 관리자 초기화
        config_manager = ConfigManager()

        # 파일 관리자 초기화
        file_manager = ExcelManager(config_manager)

        # Excel 관리자 초기화
        excel_manager = ExcelManager(config_manager)

        # 작업 선택
        task = select_task()

        if task == 0:
            print("프로그램을 종료합니다.")
            sys.exit(0)
        
        # 선택된 작업 실행

        if task == 1:
            # Description에서 신청번호 파싱하기
            request_parser = RequestParser(config_manager)
            result = request_parser.parse_request_type(file_manager)
        elif task == 2:
            # 정책파일에서 신청번호 추출하기
            request_extractor = RequestExtractor(config_manager)
            result = request_extractor.extract_request_id(file_manager)
        elif task == 3:
            # 정책파일에서 MIS ID 추가하기
            mis_id_adder = MisIdAdder(config_manager)
            result = mis_id_adder.add_mis_id(file_manager)
        elif task == 4:
            # GSAMS에서 받은 신청정보 가공하기
            aggregator = ApplicationAggregator(config_manager)
            result = aggregator.collect_applications(file_manager)
        elif task == 5:
            # 정책파일에 신청정보 추가하기
            request_info_adder = RequestInfoAdder(config_manager)
            result = request_info_adder.add_request_info(file_manager)
        elif task == 6:
            # 팔로알토 정책에서 예외처리하기
            exception_handler = ExceptionHandler(config_manager)
            result = exception_handler.paloalto_exception(file_manager)
        elif task == 7:
            # 시큐아이 정책에서 예외처리하기
            exception_handler = ExceptionHandler(config_manager)
            result = exception_handler.secui_exception(file_manager)
        elif task == 8:
            # 중복정책 공지/삭제 분류하기
            duplicate_policy_classifier = DuplicatePolicyClassifier(config_manager)
            result = duplicate_policy_classifier.organize_redundant_file(file_manager)
        elif task == 9:
            # 중복정책 분류 결과를 정책 파일에 추가하기
            duplicate_policy_classifier = DuplicatePolicyClassifier(config_manager)
            result = duplicate_policy_classifier.add_duplicate_status(file_manager)
        elif task == 10:
            # 두 개의 미사용 정보를 하나로 합치기(Pri, Sec)
            merge_handler = MergeHitcount(config_manager)
            result = merge_handler.mergehitcounts(file_manager)
        elif task == 11:
            # 미사용 정책 정보를 정책 파일에 추가하기
            policy_usage_processor = PolicyUsageProcessor(config_manager)
            result = policy_usage_processor.add_usage_status(file_manager)
        elif task == 12:
            # 미사용 예외 정보를 정책 파일에 업데이트하기
            policy_usage_processor = PolicyUsageProcessor(config_manager)
            result = policy_usage_processor.update_excepted_usage(file_manager)
        elif task == 13:
            # 정리대상 별 공지파일 분류하기
            cnotification_classifier = NotificationClassifier(config_manager)
            result = notification_classifier.classify_notifications(file_manager, excel_manager)
        elif task == 14:
            # 자동연장확인
            auto_renewal_checker = AutoRenewalChecker(config_manager)
            result = auto_renewal_checker.renewal_check(file_manager)

        if reulst:
            print("작업이 성공적으로 완료되었습니다.")
        else:
            print("작업이 실패했습니다.")
        
    except Exception as e:
        logger.exception(f"프로그램 실행 중 오류 발생: {e}")
        print(f"오류가 발생했습니다: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()