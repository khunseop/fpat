#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FPAT (Firewall Policy Analysis Tool) 통합 CLI 진입점
"""

import argparse
import sys
import os
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
    
    # 1. extract 명령어
    extract_parser = subparsers.add_parser('extract', help='방화벽 데이터 추출 (firewall_module)')
    
    # 2. analyze 명령어
    analyze_parser = subparsers.add_parser('analyze', help='정책 분석 (firewall_analyzer: 중복/Shadow)')
    
    # 3. process 명령어
    process_parser = subparsers.add_parser('process', help='정책 삭제 프로세스 처리 (policy_deletion_processor)')

    # 4. checker 명령어 (파라미터 체크 도구 웹 UI)
    checker_parser = subparsers.add_parser('checker', help='PaloAlto 파라미터 체크 웹 UI 실행')
    checker_parser.add_argument('--port', type=int, default=5000, help='웹 서버 포트 (기본값: 5000)')

    # 인자가 없으면 도움말 출력
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # 하위 명령어로 분기
    cmd = sys.argv[1]
    
    if cmd == 'extract':
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        extract_main()
    elif cmd == 'analyze':
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        analyze_main()
    elif cmd == 'process':
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        process_main()
    elif cmd == 'checker':
        try:
            from fpat.paloalto_parameter_checker.app import app
            port = int(sys.argv[sys.argv.index('--port')+1]) if '--port' in sys.argv else 5000
            logger.info(f"파라미터 체크 웹 서버를 시작합니다: http://localhost:{port}")
            app.run(host='0.0.0.0', port=port)
        except Exception as e:
            logger.error(f"웹 서버 실행 중 오류 발생: {e}")
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
