#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
방화벽 중복 정책 분석 프로세서
"""

import logging
import os
import pandas as pd
from datetime import datetime
from .base_processor import BaseProcessor
from ...firewall_analyzer.core.redundancy_analyzer import RedundancyAnalyzer
from ...firewall_analyzer.core.policy_resolver import PolicyResolver

logger = logging.getLogger(__name__)

class RedundancyProcessor(BaseProcessor):
    """방화벽 정책의 중복성을 분석하는 클래스"""
    
    def run(self, file_manager, **kwargs):
        """중복 분석을 수행합니다."""
        vendor = kwargs.get('vendor', 'paloalto')
        
        # 파일이 이미 지정되어 있는지 확인 (큐에서 가로챔)
        input_file = file_manager.select_files()
        if not input_file:
            print("분석할 정책 파일을 선택하세요 (추출된 Full Data):")
            input_file = file_manager.select_files()
            
        if not input_file:
            return False

        try:
            logger.info(f"데이터 로딩 및 분석 시작: {input_file}")
            xls = pd.ExcelFile(input_file)
            sheet_names = xls.sheet_names
            
            # 1. 정책 데이터 로드
            policy_sheet = 'policy' if 'policy' in sheet_names else sheet_names[0]
            df = pd.read_excel(xls, sheet_name=policy_sheet)
            
            # 2. 객체 해소 (address, service 시트가 있는 경우)
            if all(s in sheet_names for s in ['address', 'service']):
                logger.info("객체 정보 시트를 감지하여 데이터 해소를 수행합니다...")
                resolver = PolicyResolver()
                
                address_df = pd.read_excel(xls, sheet_name='address')
                service_df = pd.read_excel(xls, sheet_name='service')
                addr_group_df = pd.read_excel(xls, sheet_name='address_group') if 'address_group' in sheet_names else pd.DataFrame(columns=['Group Name', 'Entry'])
                svc_group_df = pd.read_excel(xls, sheet_name='service_group') if 'service_group' in sheet_names else pd.DataFrame(columns=['Group Name', 'Entry'])
                
                df = resolver.resolve(df, address_df, addr_group_df, service_df, svc_group_df)
            
            # 3. 중복 분석 수행
            analyzer = RedundancyAnalyzer()
            result_df = analyzer.analyze(df, vendor=vendor)
            
            if result_df.empty:
                logger.warning("중복 정책이 발견되지 않았습니다.")
                return True
                
            # 4. 결과 저장 (파일명 규칙 적용)
            today = datetime.now().strftime('%Y-%m-%d')
            # 입력 파일명에서 IP 추출 시도 (예: 2026-04-27_1.1.1.1_policy.xlsx)
            filename = os.path.basename(input_file)
            parts = filename.split('_')
            ip_part = parts[1] if len(parts) > 1 else 'unknown'
            
            output_file = os.path.join("outputs", f"{today}_{ip_part}_redundancy.xlsx")
            result_df.to_excel(output_file, index=False)
            
            logger.info(f"중복 분석 완료: {len(result_df)}개 항목 발견. 저장: {output_file}")
            print(f"중복 분석 결과가 '{output_file}'에 저장되었습니다.")
            
            return True

        except Exception as e:
            logger.exception(f"중복 분석 중 오류 발생: {e}")
            return False
