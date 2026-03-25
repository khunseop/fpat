#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FPAT (Firewall Policy Analysis Tool) 통합 CLI 진입점
"""

import argparse
import sys
import logging

# 모듈별 CLI 메인 함수 임포트
from fpat.firewall_module.cli import main as extract_main
from fpat.policy_deletion_processor.cli import main as process_main

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("fpat")

def main():
    parser = argparse.ArgumentParser(
        description='FPAT (Firewall Policy Analysis Tool) 통합 CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='실행할 명령')
    
    # 1. extract 명령어 (firewall_module 연동)
    extract_parser = subparsers.add_parser('extract', help='방화벽 데이터 추출 (firewall_module)')
    # firewall_module.cli.create_parser()의 인자들을 복사해오거나, 
    # 간단히 구현하기 위해 해당 모듈의 main을 직접 호출하도록 유도 (sys.argv 재구제)
    
    # 2. process 명령어 (policy_deletion_processor 연동)
    process_parser = subparsers.add_parser('process', help='정책 삭제 프로세스 처리 (policy_deletion_processor)')

    # 인자가 없으면 도움말 출력
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # 하위 명령어로 분기
    cmd = sys.argv[1]
    
    if cmd == 'extract':
        # 'fpat extract ...' -> 'fpat.firewall_module.cli ...'
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        extract_main()
    elif cmd == 'process':
        # 'fpat process ...' -> 'fpat.policy_deletion_processor.cli ...'
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        process_main()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
