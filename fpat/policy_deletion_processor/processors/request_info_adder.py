#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
신청 정보 추가 기능을 제공하는 모듈
"""

import logging
import pandas as pd

from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class RequestInfoAdder(BaseProcessor):
    """신청 정보 추가 기능을 제공하는 클래스"""
    
    def run(self, file_manager, **kwargs):
        """파일에 신청 정보를 추가합니다."""
        return self.add_request_info(file_manager)
    
    def read_and_process_excel(self, file):
        """
        Excel 파일을 읽고 초기 처리합니다.
        """
        df = pd.read_excel(file)
        # 문자열 'nan'이나 실제 NaN 값을 처리
        df.replace({'nan': None}, inplace=True)
        return df

    def _safe_to_datetime(self, val):
        """날짜 형식을 안전하게 변환합니다. (1900-01-01 이전/오류 데이터 처리 강화)"""
        if pd.isna(val) or val == "" or str(val).strip() in ["1900-01-01", "1900-01-01 00:00:00", "1900-01-00", "1900-01-00 00:00:00", "0", "00:00:00", "1899-12-30"]:
            return pd.Timestamp("1900-01-01")
        try:
            # 숫자로 들어오는 경우 처리 (Excel serial date)
            if isinstance(val, (int, float)):
                return pd.to_datetime(val, unit='D', origin='1899-12-30').normalize()
            dt = pd.to_datetime(val).normalize()
            # 1900-01-01 미만인 경우 보정 (1899년 표시 방지)
            if dt < pd.Timestamp("1900-01-01"):
                return pd.Timestamp("1900-01-01")
            return dt
        except:
            return pd.Timestamp("1900-01-01")
    
    def match_and_update_df(self, rule_df, info_df):
        """
        조건에 따라 DataFrame의 값을 매칭 및 업데이트합니다. (Dictionary 해시맵 O(1) 최적화)
        
        Args:
            rule_df (DataFrame): 규칙 DataFrame
            info_df (DataFrame): 정보 DataFrame
        """
        # 날짜 컬럼 안전하게 변환
        rule_df['End Date'] = rule_df['End Date'].apply(self._safe_to_datetime)
        info_df['REQUEST_END_DATE'] = info_df['REQUEST_END_DATE'].apply(self._safe_to_datetime)

        # O(1) 검색을 위한 해시맵(Dictionary) 구축
        # info_df를 원래 인덱스 순서대로 정렬하여, 원본 코드의 subset.sort_index().iloc[0] 로직과 동일하게 첫 번째 매칭값을 사용
        info_df_sorted = info_df.sort_index()
        info_records = info_df_sorted.to_dict('records')
        
        dict_group_cond1 = {}
        dict_group_cond2 = {}
        dict_group_cond3 = {}
        dict_normal_cond = {}
        
        for row in info_records:
            req_id = str(row.get('REQUEST_ID'))
            mis_id = str(row.get('MIS_ID'))
            end_date = row.get('REQUEST_END_DATE')
            write_person = str(row.get('WRITE_PERSON_ID'))
            requester = str(row.get('REQUESTER_ID'))
            
            # Cond 1: (REQUEST_ID, MIS_ID)
            k1 = (req_id, mis_id)
            if k1 not in dict_group_cond1: dict_group_cond1[k1] = row
            
            # Cond 2: (REQUEST_ID, REQUEST_END_DATE, WRITE_PERSON_ID)
            k2 = (req_id, end_date, write_person)
            if k2 not in dict_group_cond2: dict_group_cond2[k2] = row
            
            # Cond 3: (REQUEST_ID, REQUEST_END_DATE, REQUESTER_ID)
            k3 = (req_id, end_date, requester)
            if k3 not in dict_group_cond3: dict_group_cond3[k3] = row
            
            # Cond Normal: (REQUEST_ID)
            if req_id not in dict_normal_cond: dict_normal_cond[req_id] = row

        # 업데이트 대상 컬럼 미리 생성 (성능 경고 방지 및 속도 향상)
        for col in info_df.columns:
            if col not in rule_df.columns:
                rule_df[col] = None

        total = len(rule_df)
        for i, (idx, row) in enumerate(rule_df.iterrows()):
            print(f"\r신청 정보 매칭 중: {i + 1}/{total}", end='', flush=True)
            
            req_type = str(row.get('Request Type'))
            req_id = str(row.get('Request ID'))
            mis_id = str(row.get('MIS ID'))
            end_date = row.get('End Date')
            req_user = str(row.get('Request User'))
            
            first = None
            if req_type == 'GROUP':
                k1 = (req_id, mis_id)
                k2 = (req_id, end_date, req_user)
                
                # 원본 필터링 로직 순서대로 매칭 시도
                if k1 in dict_group_cond1:
                    first = dict_group_cond1[k1]
                elif not pd.isna(end_date) and end_date != pd.Timestamp("1900-01-01"):  # 기본값(1900)은 매칭에서 제외
                    if k2 in dict_group_cond2:
                        first = dict_group_cond2[k2]
                    elif k2 in dict_group_cond3:
                        first = dict_group_cond3[k2]
            else:
                if req_id in dict_normal_cond:
                    first = dict_normal_cond[req_id]

            if first is not None:
                for col, val in first.items():
                    if col in ['REQUEST_START_DATE', 'REQUEST_END_DATE', 'Start Date', 'End Date']:
                        rule_df.at[idx, col] = self._safe_to_datetime(val)
                    else:
                        rule_df.at[idx, col] = val
            elif req_type != 'nan' and req_type != 'Unknown' and req_type != 'None':
                rule_df.at[idx, 'REQUEST_ID'] = req_id
                rule_df.at[idx, 'REQUEST_START_DATE'] = self._safe_to_datetime(row.get('Start Date'))
                rule_df.at[idx, 'REQUEST_END_DATE'] = self._safe_to_datetime(end_date)
                rule_df.at[idx, 'REQUESTER_ID'] = req_user
                rule_df.at[idx, 'REQUESTER_EMAIL'] = str(req_user) + '@samsung.com'
        
        print()  # 줄바꿈
    
    def find_auto_extension_id(self, info_df):
        """
        자동 연장 ID를 찾습니다.
        
        Args:
            info_df (DataFrame): 정보 DataFrame
            
        Returns:
            Series: 자동 연장 ID 시리즈
        """

        info_df['REQUEST_STATUS']
        if 'REQUEST_STATUS' not in info_df.columns:
            return f"Error: 'REQUEST_STATUS' 컬럼이 데이터프레임에 존재하지 않습니다."

        # 숫자형이 아닐 경우 변환 시도
        if not pd.api.types.is_numeric_dtype(info_df['REQUEST_STATUS']):
            try:
                info_df['REQUEST_STATUS'] = pd.to_numeric(info_df['REQUEST_STATUS'], errors='coerce')  # 숫자로 변환 (변환 불가능한 값은 NaN)
            except Exception as e:
                return f"Error: 'REQUEST_STATUS' 컬럼을 숫자로 변환할 수 없습니다. {e}"

        # filtered_df = info_df[info_df['REQUEST_STATUS'].isin([98, 99])]['REQUEST_ID'].drop_duplicates()
        # 정책그룹만 자동연장 -> 연장제외 된 케이스를 예외하기 위함.
        # filtered_df = info_df[
        #     ((info_df['REQUEST_STATUS'] == 98) & info_df['REQUEST_ID'].str.startswith('PS')) |
        #     (info_df['REQUEST_STATUS'] == 99)
        # ]['REQUEST_ID'].drop_duplicates()
        
        # 다시 실제로 자동연장인것만 예외처리. 날짜기반으로 검증 필요
        filtered_df = info_df[info_df['REQUEST_STATUS'] == 99]['REQUEST_ID'].drop_duplicates()

        logger.info(f"자동 연장 ID {len(filtered_df)}개를 찾았습니다.")
        return filtered_df
    
    def add_request_info(self, file_manager):
        """
        파일에 신청 정보를 추가합니다.
        
        Args:
            file_manager: 파일 관리자
            
        Returns:
            bool: 성공 여부
        """
        try:
            print('정책 파일을 선택하세요:')
            rule_file = file_manager.select_files()
            if not rule_file:
                return False
            
            print("정보 파일을 선택하세요:")
            info_file = file_manager.select_files()
            if not info_file:
                return False
            
            rule_df = self.read_and_process_excel(rule_file)
            info_df = self.read_and_process_excel(info_file)
            info_df = info_df.sort_values(by='REQUEST_END_DATE', ascending=False)
            
            auto_extension_id = self.find_auto_extension_id(info_df)
            
            self.match_and_update_df(rule_df, info_df)
            rule_df.replace({'nan': None}, inplace=True)
            
            if not auto_extension_id.empty:
                rule_df.loc[rule_df['REQUEST_ID'].isin(auto_extension_id), 'REQUEST_STATUS'] = '99'
                logger.info(f"{len(rule_df[rule_df['REQUEST_STATUS'] == '99'])}개의 정책에 자동 연장 상태를 설정했습니다.")
            
            new_file_name = file_manager.update_version(rule_file)
            rule_df.to_excel(new_file_name, index=False, engine='openpyxl')
            logger.info(f"신청 정보 매핑 결과를 '{new_file_name}'에 저장했습니다.")
            print(f"신청 정보 매핑 결과가 '{new_file_name}'에 저장되었습니다.")
            
            return True
        except Exception as e:
            logger.exception(f"신청 정보 추가 중 오류 발생: {e}")
            return False 