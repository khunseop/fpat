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
from fpat.firewall_analyzer.cli import main as analyze_main

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
    
    # 2. analyze 명령어 (firewall_analyzer 연동)
    analyze_parser = subparsers.add_parser('analyze', help='정책 분석 (firewall_analyzer: 중복/Shadow)')
    
    # 3. process 명령어 (policy_deletion_processor 연동)
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
    elif cmd == 'analyze':
        # 'fpat analyze ...' -> 'fpat.firewall_analyzer.cli ...'
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        analyze_main()
    elif cmd == 'process':
        # 'fpat process ...' -> 'fpat.policy_deletion_processor.cli ...'
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        process_main()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
