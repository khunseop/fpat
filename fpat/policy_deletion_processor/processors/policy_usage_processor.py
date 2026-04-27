#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
미사용 정책 처리 기능을 제공하는 모듈
"""

import logging
import pandas as pd

from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class PolicyUsageProcessor(BaseProcessor):
    """미사용 정책 처리 기능을 제공하는 클래스"""
    
    def run(self, file_manager, **kwargs):
        """미사용 정책 상태를 추가하거나 예외 정보를 업데이트합니다. (mode 인자 필요)"""
        mode = kwargs.get('mode', 'add')
        if mode == 'add':
            return self.add_usage_status(file_manager)
        return self.update_excepted_usage(file_manager)
    
    def _load_smart_df(self, file_path, target_sheet=None):
        """엑셀 파일에서 데이터를 스마트하게 로드합니다 (특정 시트 우선)."""
        try:
            xls = pd.ExcelFile(file_path)
            # 1. 명시적 시트 확인, 2. 'usage' 시트 확인, 3. 첫 번째 시트
            if target_sheet and target_sheet in xls.sheet_names:
                sheet_name = target_sheet
            elif 'usage' in xls.sheet_names:
                sheet_name = 'usage'
            else:
                sheet_name = 0
            
            df = pd.read_excel(xls, sheet_name=sheet_name)
            logger.info(f"파일 {file_path}에서 '{sheet_name}' 시트를 로드했습니다.")
            return df
        except Exception as e:
            logger.error(f"파일 로드 중 오류 발생 ({file_path}): {e}")
            return pd.DataFrame()

    def add_usage_status(self, file_manager):
        """
        미사용 정책 정보를 정책 파일에 추가합니다.
        
        Args:
            file_manager: 파일 관리자
            
        Returns:
            bool: 성공 여부
        """
        try:
            print("정책 파일을 선택하세요:")
            policy_file = file_manager.select_files()
            if not policy_file:
                return False
            
            print("미사용 정책 정보 파일을 선택하세요 (사용이력 합본 또는 Full Export):")
            usage_file = file_manager.select_files()
            if not usage_file:
                return False
            
            # 스마트 로딩 적용
            policy_df = self._load_smart_df(policy_file)
            usage_df = self._load_smart_df(usage_file, 'usage')
            
            if policy_df.empty or usage_df.empty:
                logger.error("데이터 로드 실패")
                return False
            
            # 미사용여부 컬럼이 없으면 추가
            if '미사용여부' not in policy_df.columns:
                policy_df['미사용여부'] = ''
            
            # 필요한 컬럼이 있는지 확인
            if 'Rule Name' not in usage_df.columns or '미사용여부' not in usage_df.columns:
                logger.error("미사용 정보 파일에 'Rule Name' 또는 '미사용여부' 컬럼이 없습니다.")
                return False
            
            # 미사용여부 데이터 매핑
            usage_map = usage_df[['Rule Name', '미사용여부']].set_index('Rule Name').to_dict()['미사용여부']
            
            # 정책 파일에 미사용여부 데이터 추가
            updated_count = 0
            total = len(policy_df)
            
            for idx, row in policy_df.iterrows():
                print(f"\r미사용 정보 업데이트 중: {idx + 1}/{total}", end='', flush=True)
                rule_name = str(row['Rule Name'])
                if rule_name in usage_map:
                    policy_df.at[idx, '미사용여부'] = usage_map[rule_name]
                    updated_count += 1
            
            print()  # 줄바꿈
            
            # 결과 저장
            output_file = file_manager.update_version(policy_file)
            policy_df.to_excel(output_file, index=False, engine='openpyxl')
            
            logger.info(f"미사용여부 정보가 추가된 파일을 '{output_file}'에 저장했습니다.")
            logger.info(f"총 {updated_count}개의 정책에 미사용여부 정보가 추가되었습니다.")
            
            print(f"미사용여부 정보가 추가된 파일이 저장되었습니다: {output_file}")
            print(f"총 {updated_count}개의 정책에 미사용여부 정보가 추가되었습니다.")
            
            return True
        
        except Exception as e:
            logger.exception(f"미사용여부 정보 추가 중 오류 발생: {e}")
            return False

    def update_excepted_usage(self, file_manager):
        """
        미사용 정책 정보를 정책 파일에 추가합니다.
        
        Args:
            file_manager: 파일 관리자
            
        Returns:
            bool: 성공 여부
        """
        try:
            print("정책 파일을 선택하세요:")
            policy_file = file_manager.select_files()
            if not policy_file:
                return False
            
            print("3개월 내 분석된 중복정책 분류 결과 파일(_정리.xlsx)을 선택하세요:")
            duplicate_file = file_manager.select_files()
            if not duplicate_file:
                return False
            
            # 스마트 로딩 적용
            policy_df = self._load_smart_df(policy_file)
            duplicate_df = self._load_smart_df(duplicate_file)
            
            if policy_df.empty or duplicate_df.empty:
                logger.error("데이터 로드 실패")
                return False

            # 필요한 컬럼이 있는지 확인
            if 'Rule Name' not in duplicate_df.columns or '미사용예외' not in duplicate_df.columns:
                logger.error("중복정책 파일에 'Rule Name' 또는 '미사용예외' 컬럼이 없습니다.")
                return False
                        
            # '미사용예외'가 True인 'Rule Name'을 집합(set)으로 저장 (검색 속도 최적화)
            exception_rules = set(duplicate_df.loc[duplicate_df['미사용예외'] == True, 'Rule Name'].astype(str))
            # 정책 파일에 미사용예외 데이터 추가
            updated_count = 0
            total = len(policy_df)

            # iterrows()를 사용하여 policy_df 순회하면서 변경
            for idx, row in policy_df.iterrows():
                print(f"\r미사용 정보 업데이트 중: {idx + 1}/{total}", end='', flush=True)
                rule_name = str(row['Rule Name'])
                if rule_name in exception_rules:
                    if policy_df.at[idx, '미사용여부'] != '미사용예외':
                        policy_df.at[idx, '미사용여부'] = '미사용예외'
                        updated_count += 1
                        
            print()  # 줄바꿈
            
            # 결과 저장
            output_file = file_manager.update_version(policy_file)
            policy_df.to_excel(output_file, index=False, engine='openpyxl')
            
            logger.info(f"미사용예외 정보가 업데이트된 파일을 '{output_file}'에 저장했습니다.")
            logger.info(f"총 {updated_count}개의 정책에 미사용예외 정보가 업데이트되었습니다.")
            
            print(f"미사용예외 정보가 업데이트된 파일이 저장되었습니다: {output_file}")
            print(f"총 {updated_count}개의 정책에 미사용예외 정보가 업데이트되었습니다.")
            
            return True
        
        except Exception as e:
            logger.exception(f"미사용예외 정보 업데이트 중 오류 발생: {e}")
            return False
