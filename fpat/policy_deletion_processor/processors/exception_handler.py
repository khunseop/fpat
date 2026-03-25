#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
방화벽 정책 예외처리 기능을 제공하는 모듈
"""

import logging
import pandas as pd
from datetime import datetime, timedelta

from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class ExceptionHandler(BaseProcessor):
    """방화벽 정책 예외처리 기능을 제공하는 클래스"""
    
    def run(self, file_manager, **kwargs):
        """예외처리를 수행합니다. (vendor 인자 필요)"""
        vendor = kwargs.get('vendor', 'paloalto')
        if vendor == 'paloalto':
            return self.paloalto_exception(file_manager)
        return self.secui_exception(file_manager)
    
    def _check_date(self, row):
        """
        날짜를 확인하여 만료 여부를 반환합니다.
        
        Args:
            row: 데이터 행
            
        Returns:
            str: 만료 여부 ('미만료' 또는 '만료')
        """
        current_date = datetime.now().date()
        try:
            end_date = pd.to_datetime(row['REQUEST_END_DATE']).date()
            return '미만료' if end_date >= current_date else '만료'
        except:
            return '만료'
    
    def paloalto_exception(self, file_manager):
        """
        팔로알토 정책에서 예외처리를 수행합니다.
        
        Args:
            file_manager: 파일 관리자
            
        Returns:
            bool: 성공 여부
        """
        try:
            print("정책 파일을 선택하세요:")
            rule_file = file_manager.select_files()
            if not rule_file:
                return False
            
            df = pd.read_excel(rule_file)
            
            current_date = datetime.now()
            three_months_ago = current_date - timedelta(days=self.config.get('timeframes.recent_policy_days', 90))
            
            # 예외 컬럼 추가
            df["예외"] = ''
            
            # 1. 고도화된 예외 처리 (신청번호 및 정책 이름 기반)
            # 신청번호 기준 예외 체크
            df['REQUEST_ID'] = df['REQUEST_ID'].fillna('')
            req_except_mask = df.apply(lambda row: self.config.is_excepted('request_ids', str(row['REQUEST_ID'])), axis=1)
            df.loc[req_except_mask, '예외'] = '예외신청정책'
            
            # 정책 이름 패턴 기준 예외 체크
            rule_except_mask = df.apply(lambda row: self.config.is_excepted('policy_rules', str(row['Rule Name'])), axis=1)
            df.loc[rule_except_mask, '예외'] = '예외정책'
         
            # 2. 신규정책 표시 (최근 3개월 이내)
            df['날짜'] = df['Rule Name'].str.extract(r'(\d{8})', expand=False)
            df['날짜'] = pd.to_datetime(df['날짜'], format='%Y%m%d', errors='coerce')
            df.loc[(df['날짜'] >= three_months_ago) & (df['날짜'] <= current_date), '예외'] = '신규정책'

            # 3. 자동연장정책 표시
            df.loc[df['REQUEST_STATUS'] == 99, '예외'] = '자동연장정책'

            # 4. 인프라정책 표시
            marker_conf = 'policy_processing.analysis_markers.paloalto'
            deny_std_rule = self.config.get(f'{marker_conf}.deny_standard_rule_name', '마스킹')
            infra_label = self.config.get(f'{marker_conf}.infrastructure_exception_label', '인프라정책')
            
            try:
                deny_std_rule_index = df[df['Rule Name'] == deny_std_rule].index[0]
                df.loc[df.index < deny_std_rule_index, '예외'] = infra_label
            except (IndexError, KeyError):
                logger.warning(f"기준 정책({deny_std_rule})을 찾을 수 없습니다.")
            
            # 5. 특수 접두사 기반 정책 표시
            infra_prefixes = tuple(self.config.get(f'{marker_conf}.infrastructure_prefixes', []))
            special_label = self.config.get(f'{marker_conf}.special_policy_label', 'XX정책')
            if infra_prefixes:
                df.loc[df['Rule Name'].str.startswith(infra_prefixes), '예외'] = special_label

            # 6. 비활성화정책 표시
            df.loc[df['Enable'] == 'N', '예외'] = '비활성화정책'
            
            # 7. 기준정책 표시
            df.loc[(df['Rule Name'].str.endswith('_Rule', na=False)) & (df['Enable'] == 'N'), '예외'] = '기준정책'
            
            # 8. 차단정책 표시
            df.loc[df['Action'] == 'deny', '예외'] = '차단정책'
            
            # 예외 컬럼을 맨 앞으로 이동
            df['예외'].fillna('', inplace=True)
            cols = list(df.columns)
            cols = ['예외'] + [col for col in cols if col != '예외']
            df = df[cols]
            
            # 만료여부 추가
            df['만료여부'] = df.apply(self._check_date, axis=1)
            
            # 날짜 컬럼 삭제
            df.drop(columns=['날짜'], inplace=True, errors='ignore')
            
            # 컬럼명 변경
            df.rename(columns={'Request Type': '신청이력'}, inplace=True)
            
            # 불필요한 컬럼 삭제
            df.drop(columns=['Request ID', 'Ruleset ID', 'MIS ID', 'Request User', 'Start Date', 'End Date'], 
                   inplace=True, errors='ignore')
            
            # 컬럼 순서 조정
            cols = list(df.columns)
            cols.insert(cols.index('예외') + 1, cols.pop(cols.index('만료여부')))
            df = df[cols]
            
            cols.insert(cols.index('예외') + 1, cols.pop(cols.index('신청이력')))
            df = df[cols]
            
            # 미사용여부 컬럼 추가
            cols.insert(cols.index('만료여부') + 1, '미사용여부')
            df = df.reindex(columns=cols)
            df['미사용여부'] = ''
            
            # 결과 저장
            new_file_name = file_manager.update_version(rule_file, False)
            df.to_excel(new_file_name, index=False, engine='openpyxl')
            
            logger.info(f"팔로알토 정책 예외처리 결과를 '{new_file_name}'에 저장했습니다.")
            print(f"팔로알토 정책 예외처리 결과가 '{new_file_name}'에 저장되었습니다.")
            return True
        
        except Exception as e:
            logger.exception(f"팔로알토 정책 예외처리 중 오류 발생: {e}")
            return False
    
    def secui_exception(self, file_manager):
        """
        시큐아이 정책에서 예외처리를 수행합니다.
        
        Args:
            file_manager: 파일 관리자
            
        Returns:
            bool: 성공 여부
        """
        try:
            print("정책 파일을 선택하세요:")
            rule_file = file_manager.select_files()
            if not rule_file:
                return False
            
            df = pd.read_excel(rule_file)
            
            current_date = datetime.now()
            three_months_ago = current_date - timedelta(days=self.config.get('timeframes.recent_policy_days', 90))

            # 예외 컬럼 추가
            df["예외"] = ''
            
            # 1. 고도화된 예외 처리 (신청번호 및 정책 이름 기반)
            # 신청번호 기준 예외 체크
            df['REQUEST_ID'] = df['REQUEST_ID'].fillna('')
            req_except_mask = df.apply(lambda row: self.config.is_excepted('request_ids', str(row['REQUEST_ID'])), axis=1)
            df.loc[req_except_mask, '예외'] = '예외신청정책'
            
            # 정책 이름(Description 또는 Rule Name) 기준 예외 체크 (시큐아이는 Rule Name이 ID인 경우가 많으므로 Name 컬럼 확인)
            name_col = 'Rule Name' if 'Rule Name' in df.columns else 'Description'
            rule_except_mask = df.apply(lambda row: self.config.is_excepted('policy_rules', str(row[name_col])), axis=1)
            df.loc[rule_except_mask, '예외'] = '예외정책'
            
            # 2. 자동연장정책 표시
            df.loc[df['REQUEST_STATUS'] == 99, '예외'] = '자동연장정책'
            
            # 3. 인프라정책 표시
            marker_conf = 'policy_processing.analysis_markers.secui'
            deny_keyword = self.config.get(f'{marker_conf}.deny_standard_description_keyword', '마스킹')
            infra_label = self.config.get(f'{marker_conf}.infrastructure_exception_label', '인프라정책')

            try:
                deny_std_rule_index = df[df['Description'].str.contains(deny_keyword, na=False)].index[0]
                df.loc[df.index < deny_std_rule_index, '예외'] = infra_label
            except (IndexError, KeyError):
                logger.warning(f"기준 정책 키워드({deny_keyword})를 찾을 수 없습니다.")

            # 4. 현재 날짜와 3달 전 날짜 사이의 날짜에 해당하는 행인 경우
            df['Start Date'] = pd.to_datetime(df['Start Date'], errors='coerce')
            df.loc[(df['Start Date'] >= three_months_ago) & (df['Start Date'] <= current_date), '예외'] = '신규정책'

            # 5. 비활성화정책 표시
            df.loc[df['Enable'] == 'N', '예외'] = '비활성화정책'
            
            # 6. 기준정책 표시
            df.loc[(df['Description'].str.contains('기준룰', na=False)) & (df['Enable'] == 'N'), '예외'] = '기준정책'
            
            # 7. 차단정책 표시
            df.loc[df['Action'] == 'deny', '예외'] = '차단정책'
            
            # 예외 컬럼을 맨 앞으로 이동
            df['예외'].fillna('', inplace=True)
            cols = list(df.columns)
            cols = ['예외'] + [col for col in cols if col != '예외']
            df = df[cols]
            
            # 만료여부 추가
            df['만료여부'] = df.apply(self._check_date, axis=1)
            
            # 컬럼명 변경
            df.rename(columns={'Request Type': '신청이력'}, inplace=True)
            
            # 불필요한 컬럼 삭제
            df.drop(columns=['Request ID', 'Ruleset ID', 'MIS ID', 'Request User', 'Start Date', 'End Date'], 
                   inplace=True, errors='ignore')
            
            # 컬럼 순서 조정
            cols = list(df.columns)
            cols.insert(cols.index('예외') + 1, cols.pop(cols.index('만료여부')))
            df = df[cols]
            
            cols.insert(cols.index('예외') + 1, cols.pop(cols.index('신청이력')))
            df = df[cols]
            
            # 미사용여부 컬럼 추가
            cols.insert(cols.index('만료여부') + 1, '미사용여부')
            df = df.reindex(columns=cols)
            df['미사용여부'] = ''
            
            # 결과 저장
            new_file_name = file_manager.update_version(rule_file, False)
            df.to_excel(new_file_name, index=False, engine='openpyxl')
            
            logger.info(f"시큐아이 정책 예외처리 결과를 '{new_file_name}'에 저장했습니다.")
            print(f"시큐아이 정책 예외처리 결과가 '{new_file_name}'에 저장되었습니다.")
            return True
        
        except Exception as e:
            logger.exception(f"시큐아이 정책 예외처리 중 오류 발생: {e}")
            return False 