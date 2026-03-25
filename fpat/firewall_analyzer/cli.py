#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Firewall Analyzer CLI

방화벽 정책의 중복성, Shadow 정책 분석 및 필터링 기능을 수행하는 CLI 인터페이스입니다.
"""

import argparse
import sys
import os
import logging
import pandas as pd
from pathlib import Path

from fpat.firewall_analyzer import (
    RedundancyAnalyzer, 
    ShadowAnalyzer, 
    PolicyFilter,
    PolicyAnalyzer
)
from fpat.policy_deletion_processor.core.config_manager import ConfigManager

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FirewallAnalyzerCLI:
    def __init__(self, config_path=None):
        self.config = ConfigManager(config_path)
        self.redundancy_analyzer = RedundancyAnalyzer()
        self.shadow_analyzer = ShadowAnalyzer()
        self.policy_filter = PolicyFilter()

    def run_analysis(self, input_file, analysis_type, vendor, output_file=None):
        """지정된 분석 작업을 수행합니다."""
        if not os.path.exists(input_file):
            logger.error(f"입력 파일을 찾을 수 없습니다: {input_file}")
            return False

        logger.info(f"데이터 로드 중: {input_file}")
        df = pd.read_excel(input_file)
        
        result_df = pd.DataFrame()
        
        if analysis_type == 'redundancy':
            logger.info("중복 정책 분석 시작...")
            result_df = self.redundancy_analyzer.analyze(df, vendor=vendor)
        elif analysis_type == 'shadow':
            logger.info("Shadow 정책 분석 시작...")
            result_df = self.shadow_analyzer.analyze(df, vendor=vendor)
        elif analysis_type == 'all':
            logger.info("전체 분석(중복 & Shadow) 시작...")
            red_df = self.redundancy_analyzer.analyze(df, vendor=vendor)
            sha_df = self.shadow_analyzer.analyze(df, vendor=vendor)
            # 결과 합치기 또는 별도 시트로 저장 로직 필요 (여기서는 단순 합치기 예시)
            result_df = pd.concat([red_df, sha_df]).drop_duplicates()
        else:
            logger.error(f"알 수 없는 분석 타입: {analysis_type}")
            return False

        if result_df.empty:
            logger.warning("분석 결과가 비어 있습니다.")
            return True

        # 출력 파일 결정
        if not output_file:
            base = os.path.splitext(input_file)[0]
            output_file = f"{base}_{analysis_type}_result.xlsx"

        result_df.to_excel(output_file, index=False)
        logger.info(f"분석 완료! 결과 저장: {output_file}")
        return True

def create_parser():
    parser = argparse.ArgumentParser(description='FPAT 방화벽 정책 분석 CLI')
    parser.add_argument('--input', '-i', required=True, help='분석할 정책 엑셀 파일 경로')
    parser.add_argument('--type', '-t', choices=['redundancy', 'shadow', 'all'], default='all', 
                        help='분석 유형 (redundancy: 중복, shadow: 가려짐, all: 전체)')
    parser.add_argument('--vendor', '-v', choices=['paloalto', 'ngf', 'mf2'], required=True, help='방화벽 벤더')
    parser.add_argument('--output', '-o', help='결과 저장 파일 경로 (선택 사항)')
    parser.add_argument('--config', '-c', help='설정 파일 경로')
    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    cli = FirewallAnalyzerCLI(config_path=args.config)
    success = cli.run_analysis(
        input_file=args.input,
        analysis_type=args.type,
        vendor=args.vendor,
        output_file=args.output
    )
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
