#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Policy Deletion Processor CLI

방화벽 정책 삭제 프로세서를 명령줄에서 실행할 수 있는 CLI 인터페이스입니다.
"""

import argparse
import sys
import os
import logging
from pathlib import Path

# 현재 모듈의 부모 디렉토리를 경로에 추가
current_dir = Path(__file__).parent
parent_dir = current_dir.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

# 상대 import 사용 (모듈 내부에서 실행 시)
try:
    from .core.config_manager import ConfigManager
    from .processors import (
        RequestParser,
        RequestExtractor,
        MisIdAdder,
        ApplicationAggregator,
        RequestInfoAdder,
        ExceptionHandler,
        DuplicatePolicyClassifier,
        MergeHitcount,
        PolicyUsageProcessor,
        NotificationClassifier
    )
    from .utils import ExcelManager, FileManager
except ImportError:
    # 절대 import 시도 (외부에서 실행 시)
    from fpat.policy_deletion_processor.core.config_manager import ConfigManager
    from fpat.policy_deletion_processor.processors import (
        RequestParser,
        RequestExtractor,
        MisIdAdder,
        ApplicationAggregator,
        RequestInfoAdder,
        ExceptionHandler,
        DuplicatePolicyClassifier,
        MergeHitcount,
        PolicyUsageProcessor,
        NotificationClassifier
    )
    from fpat.policy_deletion_processor.utils import ExcelManager, FileManager

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PolicyDeletionProcessorCLI:
    """Policy Deletion Processor CLI 클래스"""
    
    def __init__(self, config_file=None):
        """
        CLI 인스턴스를 초기화합니다.
        
        Args:
            config_file: 설정 파일 경로 (선택사항)
        """
        try:
            if config_file and os.path.exists(config_file):
                self.config = ConfigManager(config_file)
            else:
                # 기본 설정 파일 시도
                default_config = os.path.join(
                    os.path.dirname(__file__), 'core', 'config.json'
                )
                if os.path.exists(default_config):
                    self.config = ConfigManager(default_config)
                else:
                    # 설정 파일이 없으면 빈 딕셔너리로 초기화
                    logger.warning("설정 파일을 찾을 수 없습니다. 기본 설정을 사용합니다.")
                    self.config = type('Config', (), {
                        'get': lambda self, key, default=None: default,
                        'all': lambda self: {}
                    })()
        except Exception as e:
            logger.warning(f"설정 파일 로드 실패: {e}. 기본 설정을 사용합니다.")
            self.config = type('Config', (), {
                'get': lambda self, key, default=None: default,
                'all': lambda self: {}
            })()
        
        # 프로세서 초기화
        self.file_manager = FileManager(self.config)
        self.excel_manager = ExcelManager(self.config)
        self.request_parser = RequestParser(self.config)
        self.request_extractor = RequestExtractor(self.config)
        self.mis_id_adder = MisIdAdder(self.config)
        self.application_aggregator = ApplicationAggregator(self.config)
        self.request_info_adder = RequestInfoAdder(self.config)
        self.exception_handler = ExceptionHandler(self.config)
        self.duplicate_classifier = DuplicatePolicyClassifier(self.config)
        self.merge_hitcount = MergeHitcount(self.config)
        self.policy_usage_processor = PolicyUsageProcessor(self.config)
        self.notification_classifier = NotificationClassifier(self.config)
    
    def _validate_file(self, file_path):
        """파일 경로를 검증하고 절대 경로로 변환합니다."""
        if not file_path:
            return None
        
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {file_path}")
        
        if not path.is_file():
            raise ValueError(f"파일이 아닙니다: {file_path}")
        
        return str(path.absolute())
    
    def run_all(self, policy_file, output_dir=None):
        """
        모든 프로세서를 순차적으로 실행합니다.
        
        Args:
            policy_file: 정책 파일 경로
            output_dir: 출력 디렉토리 (선택사항)
        """
        try:
            policy_file = self._validate_file(policy_file)
            original_dir = os.getcwd()
            
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
                os.chdir(output_dir)
            
            logger.info(f"정책 파일 처리 시작: {policy_file}")
            logger.info("=" * 60)
            
            current_file = policy_file
            
            # 1. Request Parser - 신청 정보 파싱
            logger.info("1단계: 신청 정보 파싱")
            if not self.parse_request(current_file):
                logger.error("신청 정보 파싱 실패")
                os.chdir(original_dir)
                return False
            current_file = self.file_manager.update_version(current_file)
            logger.info(f"1단계 완료: {current_file}")
            logger.info("")
            
            # 2. Request Extractor - 신청 ID 추출
            logger.info("2단계: 신청 ID 추출")
            if not self.extract_request_id(current_file):
                logger.warning("신청 ID 추출 실패 (계속 진행)")
            logger.info("2단계 완료")
            logger.info("")
            
            logger.info("=" * 60)
            logger.info(f"처리 완료: {current_file}")
            
            os.chdir(original_dir)
            return True
            
        except Exception as e:
            logger.exception(f"전체 프로세스 실행 중 오류 발생: {e}")
            if 'original_dir' in locals():
                os.chdir(original_dir)
            return False
    
    def parse_request(self, policy_file, output_file=None):
        """신청 정보 파싱"""
        try:
            policy_file = self._validate_file(policy_file)
            
            import pandas as pd
            
            df = pd.read_excel(policy_file)
            
            total = len(df)
            for index, row in df.iterrows():
                print(f"\r신청 정보 파싱 중: {index + 1}/{total}", end='', flush=True)
                result = self.request_parser.parse_request_info(row['Rule Name'], row['Description'])
                for key, value in result.items():
                    df.at[index, key] = value
            
            print()  # 줄바꿈
            
            if output_file:
                new_file_name = output_file
            else:
                new_file_name = self.file_manager.update_version(policy_file)
            
            df.to_excel(new_file_name, index=False)
            logger.info(f"신청 유형 파싱 결과를 '{new_file_name}'에 저장했습니다.")
            return True
        except Exception as e:
            logger.exception(f"신청 정보 파싱 중 오류: {e}")
            return False
    
    def extract_request_id(self, policy_file, output_file=None):
        """신청 ID 추출"""
        try:
            policy_file = self._validate_file(policy_file)
            
            import pandas as pd
            
            df = pd.read_excel(policy_file)
            
            # 'Unknown' 값을 제외하고 고유한 Request Type 값을 추출
            unique_types = df[df['Request Type'] != 'Unknown']['Request Type'].unique()
            
            # 고유한 Request Type 값을 최대 5개 선택
            selected_types = unique_types[:5]
            
            if len(selected_types) == 0:
                logger.warning("추출할 신청 유형이 없습니다.")
                return False
            
            # 선택된 Request Type에 해당하는 데이터 추출
            selected_data = df[df['Request Type'].isin(selected_types)]
            
            if len(selected_data) == 0:
                logger.warning("추출할 신청 ID가 없습니다.")
                return False
            
            # 출력 파일명 결정
            if output_file:
                output_file_name = output_file
            else:
                request_id_prefix = self.config.get('file_naming.request_id_prefix', 'request_id_')
                output_file_name = f"{request_id_prefix}{os.path.basename(policy_file)}"
            
            # 각 Request Type별로 Request ID 값만 추출하여 중복 제거 후 Excel의 각 시트로 저장
            with pd.ExcelWriter(output_file_name) as writer:
                for request_type, group in selected_data.groupby('Request Type'):
                    unique_ids = group[['Request ID']].drop_duplicates()
                    unique_ids.to_excel(writer, sheet_name=request_type, index=False)
                    logger.info(f"신청 유형 '{request_type}'에서 {len(unique_ids)}개의 신청 ID를 추출했습니다.")
            
            logger.info(f"신청 ID 추출 결과를 '{output_file_name}'에 저장했습니다.")
            print(f"신청 ID 추출 결과가 '{output_file_name}'에 저장되었습니다.")
            return True
        except Exception as e:
            logger.exception(f"신청 ID 추출 중 오류: {e}")
            return False
    
    def add_usage_status(self, policy_file, usage_file, output_file=None):
        """미사용 정책 정보 추가"""
        try:
            policy_file = self._validate_file(policy_file)
            usage_file = self._validate_file(usage_file)
            
            import pandas as pd
            
            # 파일 로드
            policy_df = pd.read_excel(policy_file)
            usage_df = pd.read_excel(usage_file)
            
            # 미사용여부 컬럼이 없으면 추가
            if '미사용여부' not in policy_df.columns:
                policy_df['미사용여부'] = ''
            
            # 필요한 컬럼이 있는지 확인
            if 'Rule Name' not in usage_df.columns or '미사용여부' not in usage_df.columns:
                logger.error("미사용 정보 파일에 'Rule Name' 또는 '미사용여부' 컬럼이 없습니다.")
                print("미사용 정보 파일에 'Rule Name' 또는 '미사용여부' 컬럼이 없습니다.")
                print("미사용 정보 파일의 컬럼:")
                for col in usage_df.columns:
                    print(f"- {col}")
                return False
            
            # 미사용여부 데이터 매핑
            usage_map = usage_df[['Rule Name', '미사용여부']].set_index('Rule Name').to_dict()['미사용여부']
            
            # 정책 파일에 미사용여부 데이터 추가
            updated_count = 0
            total = len(policy_df)
            
            for idx, row in policy_df.iterrows():
                print(f"\r미사용 정보 업데이트 중: {idx + 1}/{total}", end='', flush=True)
                rule_name = row['Rule Name']
                if rule_name in usage_map:
                    policy_df.at[idx, '미사용여부'] = usage_map[rule_name]
                    updated_count += 1
            
            print()  # 줄바꿈
            
            # 출력 파일명 결정
            if output_file:
                output_file_name = output_file
            else:
                output_file_name = self.file_manager.update_version(policy_file)
            
            # 결과 저장
            policy_df.to_excel(output_file_name, index=False, engine='openpyxl')
            
            logger.info(f"미사용여부 정보가 추가된 파일을 '{output_file_name}'에 저장했습니다.")
            logger.info(f"총 {updated_count}개의 정책에 미사용여부 정보가 추가되었습니다.")
            
            print(f"미사용여부 정보가 추가된 파일이 저장되었습니다: {output_file_name}")
            print(f"총 {updated_count}개의 정책에 미사용여부 정보가 추가되었습니다.")
            
            return True
        
        except Exception as e:
            logger.exception(f"미사용 정보 추가 중 오류: {e}")
            return False


def create_parser():
    """argparse 파서 생성"""
    parser = argparse.ArgumentParser(
        description='방화벽 정책 삭제 프로세서 CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:
  # 모든 프로세서 실행
  python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --run-all
  
  # 신청 정보 파싱만 실행
  python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --parse-request
  
  # 신청 ID 추출만 실행
  python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --extract-request-id
  
  # 미사용 정보 추가
  python -m fpat.policy_deletion_processor.cli --policy-file policy.xlsx --usage-file usage.xlsx --add-usage-status
        """
    )
    
    parser.add_argument(
        '--policy-file', '-p',
        type=str,
        required=True,
        help='정책 파일 경로 (Excel 파일)'
    )
    
    parser.add_argument(
        '--output-file', '-o',
        type=str,
        default=None,
        help='출력 파일 경로 (선택사항, 지정하지 않으면 자동 생성)'
    )
    
    parser.add_argument(
        '--output-dir', '-d',
        type=str,
        default=None,
        help='출력 디렉토리 (선택사항)'
    )
    
    parser.add_argument(
        '--config-file', '-c',
        type=str,
        default=None,
        help='설정 파일 경로 (선택사항)'
    )
    
    parser.add_argument(
        '--usage-file', '-u',
        type=str,
        default=None,
        help='미사용 정보 파일 경로 (add-usage-status 옵션 사용 시 필요)'
    )
    
    # 작업 선택 옵션
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        '--run-all',
        action='store_true',
        help='모든 프로세서를 순차적으로 실행'
    )
    action_group.add_argument(
        '--parse-request',
        action='store_true',
        help='신청 정보 파싱만 실행'
    )
    action_group.add_argument(
        '--extract-request-id',
        action='store_true',
        help='신청 ID 추출만 실행'
    )
    action_group.add_argument(
        '--add-usage-status',
        action='store_true',
        help='미사용 정보 추가 (--usage-file 필요)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='상세 로그 출력'
    )
    
    return parser


def main():
    """메인 함수"""
    parser = create_parser()
    args = parser.parse_args()
    
    # 로깅 레벨 설정
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # CLI 인스턴스 생성
    cli = PolicyDeletionProcessorCLI(config_file=args.config_file)
    
    # 작업 실행
    success = False
    
    try:
        if args.run_all:
            success = cli.run_all(
                policy_file=args.policy_file,
                output_dir=args.output_dir
            )
        elif args.parse_request:
            success = cli.parse_request(
                policy_file=args.policy_file,
                output_file=args.output_file
            )
        elif args.extract_request_id:
            success = cli.extract_request_id(
                policy_file=args.policy_file,
                output_file=args.output_file
            )
        elif args.add_usage_status:
            if not args.usage_file:
                parser.error("--add-usage-status 옵션 사용 시 --usage-file이 필요합니다.")
            success = cli.add_usage_status(
                policy_file=args.policy_file,
                usage_file=args.usage_file,
                output_file=args.output_file
            )
        
        if success:
            logger.info("작업이 성공적으로 완료되었습니다.")
            sys.exit(0)
        else:
            logger.error("작업 실행 중 오류가 발생했습니다.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("\n작업이 사용자에 의해 중단되었습니다.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"예상치 못한 오류 발생: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
