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
        """1단계: 정책 파일 선택 -> 2단계: 가공된 신청정보(conv) 선택 -> 분석 및 업데이트 수행"""
        try:
            print("\n[!] 자동 연장 날짜 업데이트 작업을 시작합니다.")
            
            # 1. 메인 업데이트 대상 파일(정책 파일) 선택
            target_file = file_manager.select_files()
            if not target_file:
                print("\n[선택] 업데이트를 반영할 '분석 대상 정책 파일'을 선택하세요 (예: Task 5 결과물):")
                target_file = file_manager.select_files()
            if not target_file: return False

            # 2. 참조용 가공 신청정보(conv) 선택
            reference_file = file_manager.select_files()
            if not reference_file:
                print("\n[선택] 자동연장 확인을 위한 '가공된 신청정보 파일'을 선택하세요 (예: Task 4 결과물):")
                reference_file = file_manager.select_files()
            if not reference_file: return False

            logger.info(f"데이터 로드: 정책={target_file}, 신청정보={reference_file}")
            
            # 엑셀 로드 및 컬럼명 정규화 (공백 제거)
            policy_df = pd.read_excel(target_file)
            policy_df.columns = [c.strip() for c in policy_df.columns]
            
            conv_df = pd.read_excel(reference_file)
            conv_df.columns = [c.strip() for c in conv_df.columns]

            # 분석(연장 체인 확인) 수행
            renew_df = self._analyze_chains(conv_df)
            if renew_df is None: return False
            
            # 업데이트 수행
            return self.update_renewal_dates(file_manager, target_file, policy_df, renew_df)
            
        except Exception as e:
            logger.exception(f"자동 연장 체크 실행 중 오류 발생: {e}")
            return False

    def _safe_to_datetime(self, val):
        """날짜 형식을 안전하게 변환합니다."""
        if pd.isna(val) or val == "" or str(val).strip() == "1900-01-01":
            return pd.Timestamp("1900-01-01")
        try:
            return pd.to_datetime(val)
        except:
            return pd.Timestamp("1900-01-01")

    def _analyze_chains(self, df):
        """신청정보에서 연장 체인 분석"""
        # 필수 컬럼 확인
        required = ['REQUEST_ID', 'TITLE', 'REQUEST_START_DATE', 'REQUEST_END_DATE']
        missing = [c for c in required if c not in df.columns]
        if missing:
            logger.error(f"가공 신청정보 파일에 필수 컬럼이 누락되었습니다: {missing}")
            return None

        # ID와 시작일 기준으로 정렬하여 다음 신청건 매핑
        df = df.sort_values(by=['REQUEST_ID', 'REQUEST_START_DATE'], ascending=[True, True])
        df['TITLE_next_clean'] = df.groupby('REQUEST_ID')['TITLE'].shift(-1)
        return df

    def update_renewal_dates(self, file_manager, policy_file, policy_df, renew_df):
        """정책 파일에 분석된 날짜 반영"""
        try:
            # 필요한 컬럼 존재 확인
            required_cols = ['REQUEST_ID', 'TITLE', 'REQUEST_START_DATE', 'REQUEST_END_DATE', 'Start Date', 'End Date']
            missing = [c for c in required_cols if c not in policy_df.columns]
            if missing:
                logger.error(f"정책 파일에 필수 컬럼이 누락되었습니다: {missing}")
                return False

            # 매핑용 딕셔너리 구축 (renew_df 활용)
            renew_df['key1'] = renew_df['REQUEST_ID'].astype(str) + renew_df['TITLE'].astype(str)
            
            # 딕셔너리 변환 시 오류 방지를 위해 중복 제거 (정렬 순서에 따라 마지막 것이 남음)
            renew_clean = renew_df.drop_duplicates('key1', keep='last')
            
            # Lookup 1: (ID + TITLE) -> TITLE_next_clean
            lookup_next_title = renew_clean.set_index('key1')['TITLE_next_clean'].to_dict()

            # Lookup 2: (ID + TITLE) -> (START, END) 
            lookup_next_dates = renew_clean.set_index('key1')[['REQUEST_START_DATE', 'REQUEST_END_DATE']].to_dict('index')

            updated_count = 0
            total = len(policy_df)

            logger.info("날짜 비교 및 업데이트 시작...")
            for idx, row in policy_df.iterrows():
                print(f"\r처리 중: {idx + 1}/{total}", end='', flush=True)
                
                req_id = str(row['REQUEST_ID'])
                title = str(row['TITLE'])
                key_current = req_id + title
                
                # 1. 현재 정책의 다음 버전(TITLE)이 있는지 확인
                next_title = lookup_next_title.get(key_current)
                if pd.isna(next_title) or not next_title:
                    continue
                
                # 2. 다음 버전의 날짜 정보를 가져옴
                key_next = req_id + str(next_title)
                next_info = lookup_next_dates.get(key_next)
                if not next_info:
                    continue

                # 날짜 비교 로직
                curr_req_start = self._safe_to_datetime(row['REQUEST_START_DATE'])
                curr_req_end = self._safe_to_datetime(row['REQUEST_END_DATE'])
                curr_base_start = self._safe_to_datetime(row['Start Date'])
                curr_base_end = self._safe_to_datetime(row['End Date'])
                
                new_start = self._safe_to_datetime(next_info['REQUEST_START_DATE'])
                new_end = self._safe_to_datetime(next_info['REQUEST_END_DATE'])

                is_updated = False
                
                # 시작일 업데이트 조건
                if new_start > curr_req_start and new_start > curr_base_start:
                    policy_df.at[idx, 'REQUEST_START_DATE'] = new_start.strftime('%Y-%m-%d')
                    is_updated = True
                
                # 종료일 업데이트 조건
                if new_end > curr_req_end and new_end > curr_base_end:
                    policy_df.at[idx, 'REQUEST_END_DATE'] = new_end.strftime('%Y-%m-%d')
                    is_updated = True
                
                if is_updated:
                    updated_count += 1

            print()
            
            # 결과 저장
            new_file_name = file_manager.update_version(policy_file)
            policy_df.to_excel(new_file_name, index=False)
            
            logger.info(f"업데이트 완료: 총 {updated_count}건의 날짜 정보 최신화.")
            print(f"최종 결과가 저장되었습니다: {new_file_name}")
            
            return True

        except Exception as e:
            logger.exception(f"날짜 반영 중 오류 발생: {e}")
            return False
