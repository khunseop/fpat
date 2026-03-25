#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
방화벽 정책 관리 프로세스 메인 스크립트 (Refactored)
"""

import logging
import sys
import os

# 패키지 경로 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fpat.policy_deletion_processor.core.config_manager import ConfigManager
from fpat.policy_deletion_processor.core.pipeline import Pipeline
from fpat.policy_deletion_processor.utils.file_manager import FileManager
from fpat.policy_deletion_processor.utils.excel_manager import ExcelManager

def get_base_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# 로그 설정
log_path = os.path.join(get_base_dir(), 'firewall_policy_manager.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_path, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def select_task():
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
    try:
        config = ConfigManager()
        file_manager = FileManager(config)
        excel_manager = ExcelManager(config)

        task = select_task()
        if task == 0:
            print("프로그램을 종료합니다.")
            sys.exit(0)
        
        # 파이프라인 엔진을 사용하여 단일 태스크 실행
        pipeline = Pipeline(config, file_manager, excel_manager)
        pipeline.add_step(task)
        
        if pipeline.run():
            print("\n작업이 성공적으로 완료되었습니다.")
        else:
            print("\n작업이 실패했습니다.")
        
    except Exception as e:
        logger.exception(f"프로그램 실행 중 오류 발생: {e}")
        print(f"오류가 발생했습니다: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
