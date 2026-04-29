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
        """
        current_date = datetime.now().date()
        try:
            # REQUEST_END_DATE가 있으면 사용, 없으면 만료로 간주
            if pd.isna(row.get('REQUEST_END_DATE')):
                return '만료'
            end_date = pd.to_datetime(row['REQUEST_END_DATE']).date()
            return '미만료' if end_date >= current_date else '만료'
        except:
            return '만료'
    
    def paloalto_exception(self, file_manager):
        """
        팔로알토 정책에서 예외처리를 수행합니다.
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
            
            # 1. 고도화된 예외 처리 (사유 반영 및 신규 리스트 지원)
            for idx, row in df.iterrows():
                rule_name = str(row.get('Rule Name', ''))
                req_id = str(row.get('REQUEST_ID', ''))
                
                # 신청번호 기반 체크
                is_req_exc, req_reason = self.config.get_exception_info('request_ids', req_id)
                if is_req_exc:
                    df.at[idx, '예외'] = req_reason
                    continue

                # 정책명(완전일치) 기반 체크 (신규)
                is_name_exc, name_reason = self.config.get_exception_info('policy_names', rule_name)
                if is_name_exc:
                    df.at[idx, '예외'] = name_reason
                    continue

                # 정책명(패턴) 기반 체크
                is_rule_exc, rule_reason = self.config.get_exception_info('policy_rules', rule_name)
                if is_rule_exc:
                    df.at[idx, '예외'] = rule_reason
                    continue
            
            # 2. 신규정책 표시 (이미 예외가 없는 경우만)
            df['날짜'] = df['Rule Name'].str.extract(r'(\d{8})', expand=False)
            df['날짜'] = pd.to_datetime(df['날짜'], format='%Y%m%d', errors='coerce')
            df.loc[(df['예외'] == '') & (df['날짜'] >= three_months_ago) & (df['날짜'] <= current_date), '예외'] = '신규정책'

            # 3. 자동연장정책 표시 (덮어쓰기)
            df.loc[df['REQUEST_STATUS'] == 99, '예외'] = '자동연장정책'

            # 4. 인프라정책 표시 (덮어쓰기)
            marker_conf = 'policy_processing.analysis_markers.paloalto'
            deny_std_rule = self.config.get(f'{marker_conf}.deny_standard_rule_name', '마스킹')
            infra_label = self.config.get(f'{marker_conf}.infrastructure_exception_label', '인프라정책')
            
            try:
                deny_std_rows = df[df['Rule Name'] == deny_std_rule]
                if not deny_std_rows.empty:
                    deny_std_rule_index = deny_std_rows.index[0]
                    df.loc[df.index < deny_std_rule_index, '예외'] = infra_label
            except:
                pass
            
            # 5. 특수 접두사 기반 정책 표시 (덮어쓰기)
            infra_prefixes = self.config.get(f'{marker_conf}.infrastructure_prefixes', [])
            if infra_prefixes:
                infra_prefixes = tuple(infra_prefixes)
                df.loc[df['Rule Name'].str.startswith(infra_prefixes, na=False), '예외'] = self.config.get(f'{marker_conf}.special_policy_label', '특수정책')

            # 6. 비활성화정책 표시
            df.loc[df['Enable'] == 'N', '예외'] = '비활성화정책'
            
            # 7. 기준정책 표시
            df.loc[(df['Rule Name'].str.endswith('_Rule', na=False)) & (df['Enable'] == 'N'), '예외'] = '기준정책'
            
            # 8. 차단정책 표시
            df.loc[df['Action'] == 'deny', '예외'] = '차단정책'
            
            # 컬럼 정리 및 저장
            df = self._finalize_df(df)
            
            new_file_name = file_manager.update_version(rule_file, False)
            df.to_excel(new_file_name, index=False, engine='openpyxl')
            
            logger.info(f"팔로알토 정책 예외처리 완료: {new_file_name}")
            print(f"✅ 팔로알토 예외처리 완료: {new_file_name}")
            return True
        
        except Exception as e:
            logger.exception(f"팔로알토 정책 예외처리 중 오류 발생: {e}")
            return False

    def secui_exception(self, file_manager):
        """
        시큐아이 정책에서 예외처리를 수행합니다.
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
            
            # 1. 고도화된 예외 처리 (사유 반영)
            name_col = 'Rule Name' if 'Rule Name' in df.columns else 'Description'
            for idx, row in df.iterrows():
                rule_name = str(row.get(name_col, ''))
                req_id = str(row.get('REQUEST_ID', ''))
                
                is_req_exc, req_reason = self.config.get_exception_info('request_ids', req_id)
                if is_req_exc:
                    df.at[idx, '예외'] = req_reason
                    continue

                is_name_exc, name_reason = self.config.get_exception_info('policy_names', rule_name)
                if is_name_exc:
                    df.at[idx, '예외'] = name_reason
                    continue

                is_rule_exc, rule_reason = self.config.get_exception_info('policy_rules', rule_name)
                if is_rule_exc:
                    df.at[idx, '예외'] = rule_reason
                    continue
            
            # 2. 자동연장정책 표시 (덮어쓰기)
            df.loc[df['REQUEST_STATUS'] == 99, '예외'] = '자동연장정책'
            
            # 3. 인프라정책 표시 (덮어쓰기)
            marker_conf = 'policy_processing.analysis_markers.secui'
            deny_keyword = self.config.get(f'{marker_conf}.deny_standard_description_keyword', '마스킹')
            infra_label = self.config.get(f'{marker_conf}.infrastructure_exception_label', '인프라정책')

            try:
                deny_std_rows = df[df['Description'].str.contains(deny_keyword, na=False)]
                if not deny_std_rows.empty:
                    deny_std_rule_index = deny_std_rows.index[0]
                    df.loc[df.index < deny_std_rule_index, '예외'] = infra_label
            except:
                pass

            # 4. 신규정책 표시 (이미 예외가 없는 경우만)
            df['Start Date'] = pd.to_datetime(df['Start Date'], errors='coerce')
            df.loc[(df['예외'] == '') & (df['Start Date'] >= three_months_ago) & (df['Start Date'] <= current_date), '예외'] = '신규정책'

            # 5. 비활성화정책 표시
            df.loc[df['Enable'] == 'N', '예외'] = '비활성화정책'
            
            # 6. 기준정책 표시
            df.loc[(df['Description'].str.contains('기준룰', na=False)) & (df['Enable'] == 'N'), '예외'] = '기준정책'
            
            # 7. 차단정책 표시
            df.loc[df['Action'] == 'deny', '예외'] = '차단정책'
            
            # 컬럼 정리 및 저장
            df = self._finalize_df(df)
            
            new_file_name = file_manager.update_version(rule_file, False)
            df.to_excel(new_file_name, index=False, engine='openpyxl')
            
            logger.info(f"시큐아이 정책 예외처리 완료: {new_file_name}")
            print(f"✅ 시큐아이 예외처리 완료: {new_file_name}")
            return True
        
        except Exception as e:
            logger.exception(f"시큐아이 정책 예외처리 중 오류 발생: {e}")
            return False

    def _finalize_df(self, df):
        """공통적인 컬럼 정리 로직"""
        # 예외 컬럼을 맨 앞으로 이동
        df['예외'] = df['예외'].fillna('')
        cols = list(df.columns)
        if '예외' in cols:
            cols = ['예외'] + [col for col in cols if col != '예외']
            df = df[cols]
        
        # 만료여부 추가
        df['만료여부'] = df.apply(self._check_date, axis=1)
        
        # 컬럼명 변경 및 삭제
        df.rename(columns={'Request Type': '신청이력'}, inplace=True)
        df.drop(columns=['Request ID', 'Ruleset ID', 'MIS ID', 'Request User', 'Start Date', 'End Date', '날짜'], 
               inplace=True, errors='ignore')
        
        # 컬럼 순서 조정
        cols = list(df.columns)
        for col_name in ['만료여부', '신청이력']:
            if col_name in cols:
                cols.insert(cols.index('예외') + 1, cols.pop(cols.index(col_name)))
        
        # 미사용여부 컬럼 추가
        if '미사용여부' not in cols:
            if '만료여부' in cols:
                cols.insert(cols.index('만료여부') + 1, '미사용여부')
            else:
                cols.append('미사용여부')
        
        df = df.reindex(columns=cols)
        if '미사용여부' in df.columns:
            df['미사용여부'] = df['미사용여부'].fillna('')
            
        return df
