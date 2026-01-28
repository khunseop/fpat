#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Firewall Module CLI

방화벽에서 정책 및 객체 데이터를 추출하는 CLI 인터페이스입니다.
"""

import argparse
import sys
import os
import logging
import getpass
from pathlib import Path

# 상대 import 사용
try:
    from .exporter import export_policy_to_excel
    from .collector_factory import FirewallCollectorFactory
    from .exceptions import (
        FirewallError,
        FirewallConnectionError,
        FirewallAuthenticationError,
        FirewallConfigurationError,
        FirewallDataError
    )
except ImportError:
    # 절대 import 시도
    from fpat.firewall_module.exporter import export_policy_to_excel
    from fpat.firewall_module.collector_factory import FirewallCollectorFactory
    from fpat.firewall_module.exceptions import (
        FirewallError,
        FirewallConnectionError,
        FirewallAuthenticationError,
        FirewallConfigurationError,
        FirewallDataError
    )

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_parser():
    """argparse 파서 생성"""
    parser = argparse.ArgumentParser(
        description='방화벽 정책 및 객체 데이터 추출 CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예제:
  # PaloAlto 정책 추출
  python -m fpat.firewall_module.cli \\
    --vendor paloalto \\
    --hostname 192.168.1.1 \\
    --username admin \\
    --export-type policy \\
    --output ./policies.xlsx
  
  # 전체 데이터 추출 (비밀번호 프롬프트)
  python -m fpat.firewall_module.cli \\
    --vendor paloalto \\
    --hostname firewall.example.com \\
    --username admin \\
    --export-type all \\
    --output ./complete_data.xlsx
  
  # 환경 변수에서 비밀번호 읽기
  export FIREWALL_PASSWORD="your_password"
  python -m fpat.firewall_module.cli \\
    --vendor ngf \\
    --hostname 10.0.0.1 \\
    --username admin \\
    --export-type policy \\
    --output ./ngf_policies.xlsx
        """
    )
    
    # 필수 인자
    parser.add_argument(
        '--vendor', '-v',
        type=str,
        required=True,
        choices=['paloalto', 'ngf', 'mf2', 'mock'],
        help='방화벽 벤더 (paloalto, ngf, mf2, mock)'
    )
    
    parser.add_argument(
        '--hostname', '-H',
        type=str,
        required=True,
        help='방화벽 호스트명 또는 IP 주소'
    )
    
    parser.add_argument(
        '--username', '-u',
        type=str,
        required=True,
        help='방화벽 로그인 사용자명'
    )
    
    parser.add_argument(
        '--password', '-p',
        type=str,
        default=None,
        help='방화벽 로그인 비밀번호 (지정하지 않으면 프롬프트 또는 환경 변수 사용)'
    )
    
    parser.add_argument(
        '--export-type', '-t',
        type=str,
        required=True,
        choices=['policy', 'address', 'address_group', 'service', 'service_group', 'usage', 'all'],
        help='추출할 데이터 타입'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        required=True,
        help='출력 Excel 파일 경로'
    )
    
    # 선택 인자
    parser.add_argument(
        '--config-type', '-c',
        type=str,
        default='running',
        choices=['running', 'candidate'],
        help='설정 타입 (PaloAlto 전용, 기본값: running)'
    )
    
    parser.add_argument(
        '--chunk-size',
        type=int,
        default=1000,
        help='대용량 데이터 처리 시 청크 크기 (기본값: 1000)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='연결 타임아웃 (초, 기본값: 30)'
    )
    
    parser.add_argument(
        '--no-test-connection',
        action='store_true',
        help='연결 테스트 건너뛰기'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='상세 로그 출력'
    )
    
    parser.add_argument(
        '--password-env',
        type=str,
        default='FIREWALL_PASSWORD',
        help='비밀번호를 읽을 환경 변수 이름 (기본값: FIREWALL_PASSWORD)'
    )
    
    return parser


def get_password(args):
    """비밀번호를 가져옵니다 (인자, 환경 변수, 프롬프트 순서)"""
    # 1. 명령줄 인자에서 가져오기
    if args.password:
        return args.password
    
    # 2. 환경 변수에서 가져오기
    env_password = os.environ.get(args.password_env)
    if env_password:
        logger.info(f"환경 변수 '{args.password_env}'에서 비밀번호를 읽었습니다.")
        return env_password
    
    # 3. 프롬프트로 입력받기
    try:
        password = getpass.getpass(f"방화벽 비밀번호 ({args.hostname}): ")
        return password
    except (KeyboardInterrupt, EOFError):
        logger.error("비밀번호 입력이 취소되었습니다.")
        sys.exit(1)


def main():
    """메인 함수"""
    parser = create_parser()
    args = parser.parse_args()
    
    # 로깅 레벨 설정
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("상세 로그 모드 활성화")
    
    # 비밀번호 가져오기
    password = get_password(args)
    if not password:
        logger.error("비밀번호가 제공되지 않았습니다.")
        sys.exit(1)
    
    try:
        logger.info(f"방화벽 데이터 추출 시작: {args.vendor}://{args.username}@{args.hostname}")
        logger.info(f"추출 타입: {args.export_type}")
        logger.info(f"출력 파일: {args.output}")
        
        # 데이터 추출 실행
        output_file = export_policy_to_excel(
            vendor=args.vendor,
            hostname=args.hostname,
            username=args.username,
            password=password,
            export_type=args.export_type,
            output_path=args.output,
            config_type=args.config_type if args.vendor == 'paloalto' else 'running',
            chunk_size=args.chunk_size,
            progress_callback=None  # CLI에서는 로거가 진행률을 표시
        )
        
        logger.info("=" * 60)
        logger.info(f"데이터 추출이 성공적으로 완료되었습니다!")
        logger.info(f"출력 파일: {output_file}")
        
        # 파일 크기 확인
        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            file_size_mb = file_size / (1024 * 1024)
            logger.info(f"파일 크기: {file_size_mb:.2f} MB")
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        logger.info("\n작업이 사용자에 의해 중단되었습니다.")
        sys.exit(130)
    except FirewallConnectionError as e:
        logger.error(f"방화벽 연결 실패: {e}")
        sys.exit(1)
    except FirewallAuthenticationError as e:
        logger.error(f"인증 실패: {e}")
        sys.exit(1)
    except FirewallConfigurationError as e:
        logger.error(f"설정 오류: {e}")
        sys.exit(1)
    except FirewallDataError as e:
        logger.error(f"데이터 추출 실패: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"예상치 못한 오류 발생: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
