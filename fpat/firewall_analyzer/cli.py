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

    def run_analysis(self, input_file, analysis_type, vendor, output_file=None, use_logical=False):
        """지정된 분석 작업을 수행합니다."""
        if not os.path.exists(input_file):
            logger.error(f"입력 파일을 찾을 수 없습니다: {input_file}")
            return False

        logger.info(f"데이터 로드 중: {input_file}")
        
        # 1. 엑셀 파일 로드 및 객체 해소 (필요시)
        try:
            xls = pd.ExcelFile(input_file)
            sheet_names = xls.sheet_names
            
            # 정책 데이터 로드 (기본은 첫 번째 시트 또는 'policy' 시트)
            policy_sheet = 'policy' if 'policy' in sheet_names else sheet_names[0]
            df = pd.read_excel(xls, sheet_name=policy_sheet)
            
            # 객체 정보 시트 존재 여부 확인 및 리졸빙 시도
            has_objects = all(s in sheet_names for s in ['address', 'service'])
            
            if has_objects:
                logger.info("객체 정보 시트를 발견했습니다. 데이터 해소를 수행합니다...")
                from fpat.firewall_analyzer.core.policy_resolver import PolicyResolver
                
                address_df = pd.read_excel(xls, sheet_name='address')
                service_df = pd.read_excel(xls, sheet_name='service')
                addr_group_df = pd.read_excel(xls, sheet_name='address_group') if 'address_group' in sheet_names else pd.DataFrame(columns=['Group Name', 'Entry'])
                svc_group_df = pd.read_excel(xls, sheet_name='service_group') if 'service_group' in sheet_names else pd.DataFrame(columns=['Group Name', 'Entry'])
                
                resolver = PolicyResolver()
                df = resolver.resolve(df, address_df, addr_group_df, service_df, svc_group_df)
                logger.info("객체 데이터 해소 완료.")
        except Exception as e:
            logger.error(f"파일 로드 중 오류 발생: {e}")
            return False
        
        result_df = pd.DataFrame()
        
        # 2. 분석 수행 (고속 방식 analyze 우선 사용)
        if analysis_type == 'redundancy':
            if use_logical and 'Extracted Source' in df.columns:
                logger.info("중복 정책 분석 시작 (정밀 논리 분석 모드)...")
                result_df = self.redundancy_analyzer.analyze_logical(df, vendor=vendor)
            else:
                logger.info("중복 정책 분석 시작 (고속 모드)...")
                result_df = self.redundancy_analyzer.analyze(df, vendor=vendor)
                
        elif analysis_type == 'shadow':
            logger.info("Shadow 정책 분석 시작...")
            result_df = self.shadow_analyzer.analyze(df, vendor=vendor)
            
        elif analysis_type == 'all':
            logger.info("전체 분석(중복 & Shadow) 시작...")
            if use_logical and 'Extracted Source' in df.columns:
                red_df = self.redundancy_analyzer.analyze_logical(df, vendor=vendor)
            else:
                red_df = self.redundancy_analyzer.analyze(df, vendor=vendor)
            sha_df = self.shadow_analyzer.analyze(df, vendor=vendor)
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
    parser.add_argument('--logical', action='store_true', help='수학적 포함 관계 기반 정밀 분석 사용 (속도가 느림)')
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
        output_file=args.output,
        use_logical=args.logical
    )
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
