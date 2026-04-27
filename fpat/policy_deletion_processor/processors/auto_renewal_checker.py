#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
자동 연장된 정책의 날짜 정보를 업데이트하는 모듈
"""

import logging
import pandas as pd
import os
from datetime import datetime
from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class AutoRenewalChecker(BaseProcessor):
    """자동 연장 정책 날짜 업데이트 클래스"""
    
    def run(self, file_manager, **kwargs):
        """자동 연장 확인 파일을 참조하여 v3 파일의 날짜를 업데이트합니다."""
        return self.update_renewal_dates(file_manager)

    def _safe_to_datetime(self, val):
        """날짜 형식을 안전하게 변환합니다."""
        if pd.isna(val) or val == "" or str(val).strip() == "1900-01-01":
            return pd.Timestamp("1900-01-01")
        try:
            return pd.to_datetime(val)
        except:
            return pd.Timestamp("1900-01-01")

    def update_renewal_dates(self, file_manager):
        try:
            print("\n[!] 자동 연장 날짜 업데이트 작업을 시작합니다.")
            
            print("1. 정책 매핑 결과 파일(v3)을 선택하세요:")
            v3_file = file_manager.select_files()
            if not v3_file: return False
            
            print("2. 자동연장 확인 파일(renew)을 선택하세요:")
            renew_file = file_manager.select_files()
            if not renew_file: return False

            logger.info("데이터 로드 중...")
            v3_df = pd.read_excel(v3_file)
            renew_df = pd.read_excel(renew_file)

            # 필요한 컬럼 존재 확인
            required_v3 = ['REQUEST_ID', 'TITLE', 'REQUEST_START_DATE', 'REQUEST_END_DATE', 'Start Date', 'End Date']
            required_renew = ['REQUEST_ID', 'TITLE', 'TITLE_next_clean', 'REQUEST_START_DATE_next', 'REQUEST_END_DATE_next']
            
            for df, req, name in [(v3_df, required_v3, "v3"), (renew_df, required_renew, "renew")]:
                missing = [c for c in req if c not in df.columns]
                if missing:
                    logger.error(f"{name} 파일에 필수 컬럼이 누락되었습니다: {missing}")
                    return False

            # 매핑용 딕셔너리 구축 (속도 최적화)
            # Lookup 1: (ID + TITLE) -> TITLE_next_clean
            renew_df['key1'] = renew_df['REQUEST_ID'].astype(str) + renew_df['TITLE'].astype(str)
            lookup_next_title = renew_df.set_index('key1')['TITLE_next_clean'].to_dict()

            # Lookup 2: (ID + TITLE_next_clean) -> (START_next, END_next)
            renew_df['key2'] = renew_df['REQUEST_ID'].astype(str) + renew_df['TITLE_next_clean'].astype(str)
            lookup_next_dates = renew_df.set_index('key2')[['REQUEST_START_DATE_next', 'REQUEST_END_DATE_next']].to_dict('index')

            updated_count = 0
            total = len(v3_df)

            logger.info("날짜 비교 및 업데이트 시작...")
            for idx, row in v3_df.iterrows():
                print(f"\r처리 중: {idx + 1}/{total}", end='', flush=True)
                
                req_id = str(row['REQUEST_ID'])
                title = str(row['TITLE'])
                
                # 1단계: 다음 TITLE 찾기
                key_v3 = req_id + title
                next_title = lookup_next_title.get(key_v3)
                
                if pd.isna(next_title) or not next_title:
                    continue
                
                # 2단계: 다음 날짜 정보 찾기
                key_next = req_id + str(next_title)
                next_info = lookup_next_dates.get(key_next)
                
                if not next_info:
                    continue

                # 날짜 객체 변환 및 비교
                curr_req_start = self._safe_to_datetime(row['REQUEST_START_DATE'])
                curr_req_end = self._safe_to_datetime(row['REQUEST_END_DATE'])
                curr_base_start = self._safe_to_datetime(row['Start Date'])
                curr_base_end = self._safe_to_datetime(row['End Date'])
                
                new_start = self._safe_to_datetime(next_info['REQUEST_START_DATE_next'])
                new_end = self._safe_to_datetime(next_info['REQUEST_END_DATE_next'])

                is_updated = False
                
                # 시작일 업데이트 조건: 신규값이 기존 REQUEST_START_DATE와 Start Date보다 모두 클 때
                if new_start > curr_req_start and new_start > curr_base_start:
                    v3_df.at[idx, 'REQUEST_START_DATE'] = new_start.strftime('%Y-%m-%d')
                    is_updated = True
                
                # 종료일 업데이트 조건: 신규값이 기존 REQUEST_END_DATE와 End Date보다 모두 클 때
                if new_end > curr_req_end and new_end > curr_base_end:
                    v3_df.at[idx, 'REQUEST_END_DATE'] = new_end.strftime('%Y-%m-%d')
                    is_updated = True
                
                if is_updated:
                    updated_count += 1

            print() # 줄바꿈
            
            # 결과 저장
            new_file_name = file_manager.update_version(v3_file)
            v3_df.to_excel(new_file_name, index=False)
            
            logger.info(f"업데이트 완료: 총 {updated_count}건의 날짜 정보가 최신화되었습니다.")
            print(f"결과가 저장되었습니다: {new_file_name}")
            
            return True

        except Exception as e:
            logger.exception(f"자동 연장 체크 중 오류 발생: {e}")
            return False
