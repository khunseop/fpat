#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
자동 연장된 정책의 정보를 분석하고 날짜를 업데이트하는 모듈
"""

import logging
import pandas as pd
import os
from datetime import datetime
from fpat.policy_deletion_processor.processors.base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class AutoRenewalChecker(BaseProcessor):
    """자동 연장 정책 분석 및 날짜 업데이트 클래스"""
    
    def run(self, file_manager, **kwargs):
        """1단계 분석(Renew 파일 생성)과 2단계 업데이트(v3 반영)를 연속 수행합니다."""
        # 1단계: 신청정보 가공 파일로부터 자동연장 관계 분석
        renew_df, conv_file = self.create_renew_map(file_manager)
        if renew_df is None:
            return False
            
        # 2단계: 분석된 정보를 바탕으로 정책 매핑 파일(v3) 업데이트
        return self.update_renewal_dates(file_manager, renew_df)

    def _safe_to_datetime(self, val):
        """날짜 형식을 안전하게 변환합니다."""
        if pd.isna(val) or val == "" or str(val).strip() == "1900-01-01":
            return pd.Timestamp("1900-01-01")
        try:
            return pd.to_datetime(val)
        except:
            return pd.Timestamp("1900-01-01")

    def create_renew_map(self, file_manager):
        """가공된 신청정보(conv)에서 자동연장 체인을 분석하여 리스트를 만듭니다."""
        try:
            print("\n[단계 1] 자동 연장 체인 분석 (Conv 파일)")
            print("-" * 40)
            print("가공된 신청정보 파일(Conv_...)을 선택하세요:")
            conv_file = file_manager.select_files()
            if not conv_file: return None, None

            logger.info(f"신청정보 로드 및 분석 중: {conv_file}")
            df = pd.read_excel(conv_file)

            # 필수 컬럼 확인
            required = ['REQUEST_ID', 'TITLE', 'REQUEST_START_DATE', 'REQUEST_END_DATE']
            if not all(c in df.columns for c in required):
                logger.error(f"필수 컬럼이 누락되었습니다: {required}")
                return None, None

            # ID와 시작일 기준으로 정렬
            df = df.sort_values(by=['REQUEST_ID', 'REQUEST_START_DATE'], ascending=[True, True])

            # 다음 신청 건(Next) 정보 매핑
            # 같은 REQUEST_ID 내에서 다음 행의 데이터를 가져옴
            df['TITLE_next_clean'] = df.groupby('REQUEST_ID')['TITLE'].shift(-1)
            df['REQUEST_START_DATE_next'] = df.groupby('REQUEST_ID')['REQUEST_START_DATE'].shift(-1)
            df['REQUEST_END_DATE_next'] = df.groupby('REQUEST_ID')['REQUEST_END_DATE'].shift(-1)

            # 분석 결과(Renew) 파일 저장
            renew_file = file_manager.update_version(conv_file)
            # 파일명에 'renew' 표시를 위해 이름 조정 (옵션)
            renew_file = renew_file.replace('.xlsx', '_renew.xlsx')
            df.to_excel(renew_file, index=False)
            
            logger.info(f"자동연장 분석 완료: {renew_file}")
            print(f"-> 분석 완료: {len(df.dropna(subset=['TITLE_next_clean']))}개의 연장 체인 발견.")
            
            return df, renew_file

        except Exception as e:
            logger.exception(f"사전 분석 중 오류 발생: {e}")
            return None, None

    def update_renewal_dates(self, file_manager, renew_df):
        """분석된 정보를 정책 매핑 결과(v3)에 반영합니다."""
        try:
            print("\n[단계 2] 정책 파일 날짜 업데이트 (v3 파일)")
            print("-" * 40)
            print("업데이트할 정책 매핑 결과 파일(v3)을 선택하세요:")
            v3_file = file_manager.select_files()
            if not v3_file: return False

            v3_df = pd.read_excel(v3_file)

            # 필요한 컬럼 존재 확인
            required_v3 = ['REQUEST_ID', 'TITLE', 'REQUEST_START_DATE', 'REQUEST_END_DATE', 'Start Date', 'End Date']
            if not all(c in v3_df.columns for c in required_v3):
                logger.error(f"v3 파일에 필수 컬럼이 누락되었습니다: {required_v3}")
                return False

            # 매핑용 딕셔너리 구축 (renew_df 활용)
            # Lookup 1: (ID + TITLE) -> TITLE_next_clean
            renew_df['key1'] = renew_df['REQUEST_ID'].astype(str) + renew_df['TITLE'].astype(str)
            lookup_next_title = renew_df.set_index('key1')['TITLE_next_clean'].to_dict()

            # Lookup 2: (ID + TITLE_next_clean) -> (START_next, END_next)
            # Key2는 (ID + TITLE)과 매칭되어야 하므로 renew_df의 원본 컬럼 사용
            lookup_next_dates = renew_df.set_index('key1')[['REQUEST_START_DATE', 'REQUEST_END_DATE']].to_dict('index')

            updated_count = 0
            total = len(v3_df)

            logger.info("날짜 비교 및 업데이트 시작...")
            for idx, row in v3_df.iterrows():
                print(f"\r처리 중: {idx + 1}/{total}", end='', flush=True)
                
                req_id = str(row['REQUEST_ID'])
                title = str(row['TITLE'])
                
                # 1. 현재 v3의 정책이 분석 리스트에 있는지 확인 (ID + TITLE)
                key_v3 = req_id + title
                next_title = lookup_next_title.get(key_v3)
                
                if pd.isna(next_title) or not next_title:
                    continue
                
                # 2. 다음 버전(next_title)의 날짜 정보를 분석 리스트에서 가져옴
                key_next = req_id + str(next_title)
                next_info = lookup_next_dates.get(key_next)
                
                if not next_info:
                    continue

                # 날짜 객체 변환
                curr_req_start = self._safe_to_datetime(row['REQUEST_START_DATE'])
                curr_req_end = self._safe_to_datetime(row['REQUEST_END_DATE'])
                curr_base_start = self._safe_to_datetime(row['Start Date'])
                curr_base_end = self._safe_to_datetime(row['End Date'])
                
                new_start = self._safe_to_datetime(next_info['REQUEST_START_DATE'])
                new_end = self._safe_to_datetime(next_info['REQUEST_END_DATE'])

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

            print()
            
            # 최종 결과 저장
            new_file_name = file_manager.update_version(v3_file)
            v3_df.to_excel(new_file_name, index=False)
            
            logger.info(f"업데이트 완료: 총 {updated_count}건의 날짜 정보 최신화.")
            print(f"최종 결과가 저장되었습니다: {new_file_name}")
            
            return True

        except Exception as e:
            logger.exception(f"날짜 반영 중 오류 발생: {e}")
            return False
