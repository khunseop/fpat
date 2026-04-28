#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
자동 연장된 정책의 정보를 정밀 분석하고 날짜를 업데이트하는 모듈
(과거 정밀 로직 복구 및 업데이트 기능 통합본)
"""

import logging
import pandas as pd
import os
import re
from datetime import datetime
from fpat.policy_deletion_processor.processors.base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class AutoRenewalChecker(BaseProcessor):
    """자동 연장 정책 분석 및 날짜 업데이트 클래스"""
    
    def run(self, file_manager, **kwargs):
        """1단계: 정밀 분석(Chain Analysis) -> 2단계: 정책 반영(Update)"""
        try:
            print("\n[!] 자동 연장 정밀 분석 및 날짜 업데이트를 시작합니다.")
            
            # 1. 가공된 신청정보(conv) 선택 및 분석
            renew_df = self._analyze_chains_precision(file_manager)
            if renew_df is None or renew_df.empty:
                logger.warning("자동 연장으로 판단된 데이터가 없습니다.")
                return False
                
            # 2. 정책 파일(policy) 선택 및 업데이트
            return self._update_policy_dates(file_manager, renew_df)
            
        except Exception as e:
            logger.exception(f"실행 중 오류 발생: {e}")
            return False

    def _remove_bracket_prefix(self, text):
        """[괄호]로 시작하는 머리말을 반복적으로 제거합니다."""
        bracket_pattern = self.config.get('policy_processing.aggregation.title_bracket_pattern', r'^\[([^\[\]]{1,8})\]')
        if isinstance(text, str) and text.startswith('['):
            while True:
                match = re.match(bracket_pattern, text)
                if match:
                    text = text[len(match.group(0)):].strip()
                else:
                    break
        return text

    def _safe_to_datetime(self, val):
        """날짜 형식을 안전하게 변환합니다."""
        if pd.isna(val) or val == "" or str(val).strip() == "1900-01-01":
            return pd.Timestamp("1900-01-01")
        try:
            return pd.to_datetime(val)
        except:
            return pd.Timestamp("1900-01-01")

    def _analyze_chains_precision(self, file_manager):
        """과거 정밀 로직: 종료일-시작일 매칭 및 작성자/제목 검증"""
        print("\n[단계 1] 자동 연장 체인 정밀 분석")
        print("-" * 40)
        print("가공된 신청정보 파일(Conv_...)을 선택하세요:")
        conv_file = file_manager.select_files()
        if not conv_file: return None

        logger.info(f"정밀 분석 시작: {conv_file}")
        df = pd.read_excel(conv_file)
        
        # 필수 컬럼 확인
        required = ['REQUEST_ID', 'TITLE', 'REQUEST_START_DATE', 'REQUEST_END_DATE', 'WRITE_PERSON_ID']
        if not all(c in df.columns for c in required):
            logger.error(f"필수 컬럼 누락: {[c for c in required if c not in df.columns]}")
            return None

        # 날짜 형식 표준화
        df['REQUEST_START_DATE'] = pd.to_datetime(df['REQUEST_START_DATE'])
        df['REQUEST_END_DATE'] = pd.to_datetime(df['REQUEST_END_DATE'])

        # 1. 정밀 매칭 (Self Merge): 앞 건의 종료일 == 뒤 건의 시작일
        merged = pd.merge(
            df, df,
            left_on=['REQUEST_ID', 'REQUEST_END_DATE'],
            right_on=['REQUEST_ID', 'REQUEST_START_DATE'],
            suffixes=('_prev', '_next')
        )

        if merged.empty:
            logger.info("날짜가 이어지는 신청 건을 찾지 못했습니다.")
            return pd.DataFrame()

        # 2. 제목 정제 및 동일성 검사
        merged['TITLE_prev_clean'] = merged['TITLE_prev'].apply(self._remove_bracket_prefix)
        merged['TITLE_next_clean'] = merged['TITLE_next'].apply(self._remove_bracket_prefix)

        # 3. 작성자가 같고 정제된 제목이 같은 경우만 필터링 (진짜 연장)
        valid_chains = merged[
            (merged['WRITE_PERSON_ID_prev'] == merged['WRITE_PERSON_ID_next']) &
            (merged['TITLE_prev_clean'] == merged['TITLE_next_clean'])
        ].copy()

        # 분석 결과 저장
        today = datetime.now().strftime('%Y-%m-%d')
        output_file = os.path.join("outputs", f"{today}_renewal_chain.xlsx")
        valid_chains.to_excel(output_file, index=False)
        
        print(f"-> 정밀 분석 완료: {len(valid_chains)}개의 유효 연장 체인 식별.")
        print(f"-> 분석 리스트 저장: {output_file}")
        return valid_chains

    def _update_policy_dates(self, file_manager, renew_df):
        """분석된 체인을 정책 파일에 반영"""
        print("\n[단계 2] 정책 파일 날짜 업데이트")
        print("-" * 40)
        print("업데이트할 분석 대상 정책 파일을 선택하세요:")
        policy_file = file_manager.select_files()
        if not policy_file: return False

        policy_df = pd.read_excel(policy_file)
        policy_df.columns = [c.strip() for c in policy_df.columns]

        # 매핑용 사전 구축: (ID + 원본TITLE) -> (Next START, Next END)
        # renew_df에서 _prev가 현재 값, _next가 연장된 값임
        renew_df['key_lookup'] = renew_df['REQUEST_ID'].astype(str) + renew_df['TITLE_prev'].astype(str)
        # 중복 시 마지막(가장 최신) 것 유지
        lookup_map = renew_df.drop_duplicates('key_lookup', keep='last').set_index('key_lookup')[['REQUEST_START_DATE_next', 'REQUEST_END_DATE_next']].to_dict('index')

        updated_count = 0
        total = len(policy_df)

        for idx, row in policy_df.iterrows():
            print(f"\r날짜 반영 중: {idx + 1}/{total}", end='', flush=True)
            
            key = str(row.get('REQUEST_ID', '')) + str(row.get('TITLE', ''))
            next_info = lookup_map.get(key)
            
            if not next_info: continue

            # 날짜 비교 및 업데이트
            curr_req_start = self._safe_to_datetime(row.get('REQUEST_START_DATE'))
            curr_req_end = self._safe_to_datetime(row.get('REQUEST_END_DATE'))
            curr_base_start = self._safe_to_datetime(row.get('Start Date'))
            curr_base_end = self._safe_to_datetime(row.get('End Date'))
            
            new_start = self._safe_to_datetime(next_info['REQUEST_START_DATE_next'])
            new_end = self._safe_to_datetime(next_info['REQUEST_END_DATE_next'])

            is_updated = False
            if new_start > curr_req_start and new_start > curr_base_start:
                policy_df.at[idx, 'REQUEST_START_DATE'] = new_start.strftime('%Y-%m-%d')
                is_updated = True
            if new_end > curr_req_end and new_end > curr_base_end:
                policy_df.at[idx, 'REQUEST_END_DATE'] = new_end.strftime('%Y-%m-%d')
                is_updated = True
            
            if is_updated: updated_count += 1

        print()
        
        # 결과 저장
        new_file_name = file_manager.update_version(policy_file)
        policy_df.to_excel(new_file_name, index=False)
        
        print(f"✅ 업데이트 완료: 총 {updated_count}건의 날짜가 최신화되었습니다.")
        print(f"최종 결과 저장: {new_file_name}")
        return True
