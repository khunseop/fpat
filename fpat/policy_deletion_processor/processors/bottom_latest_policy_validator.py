#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
하단 최신 정책 검증 모듈
동일 신청번호 내에서 최신 날짜의 정책이 하단(또는 특정 위치)에 있는지 검증하고 분류합니다.
"""

import logging
import pandas as pd
import os
from fpat.policy_deletion_processor.processors.base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class BottomLatestPolicyValidator(BaseProcessor):
    """하단 최신 정책 검증 및 분류 클래스"""
    
    def run(self, file_manager, **kwargs):
        """검증 태스크 실행"""
        try:
            print("\n[!] 하단 최신 정책 검증 작업을 시작합니다.")
            
            # 1. 파일 선택 (예외처리 완료된 파일)
            file_name = file_manager.select_files()
            if not file_name:
                return False

            logger.info(f"데이터 로드 중: {file_name}")
            # 모든 시트를 읽지 않고 분석을 위해 첫 번째 시트(사용이력) 로드
            df = pd.read_excel(file_name)
            
            if '신청이력' not in df.columns or 'Seq' not in df.columns or 'REQUEST_ID' not in df.columns:
                logger.error("필수 컬럼이 누락되었습니다. (신청이력, Seq, REQUEST_ID)")
                return False

            # 2. 분석용 데이터 추출 (신청이력 != Unknown)
            # 'Unknown' 문자열 및 NaN 처리
            analysis_df = df[
                (df['신청이력'].notna()) & 
                (df['신청이력'].astype(str).str.upper() != 'UNKNOWN')
            ].copy()

            if analysis_df.empty:
                logger.warning("분석할 유효한 신청이력 데이터가 없습니다.")
                return False

            # 3. 검증 로직 실행 (find_seq_mismatches)
            print("-> 하단 최신 정책 분석 중...")
            validation_results = self._find_seq_mismatches(analysis_df)
            
            # 4. 메인 시트 업데이트 (미사용여부 컬럼 기입)
            print("-> 메인 데이터 업데이트 중...")
            if '미사용여부' not in df.columns:
                df['미사용여부'] = ""
            
            # 매칭 대상이 되는 latest_seq들만 모으기
            all_latest_seqs = []
            for seq_list in validation_results['latest_seq']:
                all_latest_seqs.extend(seq_list)
            
            # Seq가 latest_seq 리스트에 포함되면 '하단최신정책' 마킹
            # (단, validation_results에 포함된 REQUEST_ID인 경우만)
            target_ids = set(validation_results['REQUEST_ID'])
            df.loc[
                (df['REQUEST_ID'].isin(target_ids)) & (df['Seq'].isin(all_latest_seqs)), 
                '미사용여부'
            ] = '하단최신정책'

            # 5. 멀티 시트로 저장
            output_file = file_manager.update_version(file_name)
            
            with pd.ExcelWriter(output_file, engine='xlsxwriter') as writer:
                # 메인 데이터 저장 (사용이력)
                df.to_excel(writer, sheet_name='usage', index=False)
                # 검증 결과 저장
                # 리스트 형태인 latest_seq를 보기 좋게 문자열로 변환하여 저장
                save_v_df = validation_results.copy()
                save_v_df['latest_seq'] = save_v_df['latest_seq'].astype(str)
                save_v_df.to_excel(writer, sheet_name='검증', index=False)

            logger.info(f"검증 완료 및 파일 저장: {output_file}")
            print(f"✅ 검증 완료! (분류된 정책: {len(all_latest_seqs)}건)")
            print(f"📄 결과 저장: {output_file}")
            
            return True

        except Exception as e:
            logger.exception(f"하단 최신 정책 검증 중 오류 발생: {e}")
            return False

    def _find_seq_mismatches(self, df):
        """REQUEST_ID별로 최신 날짜와 Seq 위치를 비교 분석"""
        df = df.copy()
        # 날짜 형식 변환
        df["REQUEST_START_DATE"] = pd.to_datetime(df["REQUEST_START_DATE"], errors="coerce")

        results = []
        for rid, group in df.groupby("REQUEST_ID"):
            if pd.isna(rid): continue
            
            # 최신 날짜 찾기
            max_date = group["REQUEST_START_DATE"].max()
            if pd.isna(max_date): continue
            
            # 최신 날짜에 해당하는 모든 Seq (latest_seqs)
            latest_seqs = group.loc[group["REQUEST_START_DATE"] == max_date, "Seq"].unique().tolist()
            # 전체 중 가장 낮은 Seq (lowest_seq)
            lowest_seq = group["Seq"].min()

            # 수동 로직: lowest_seq가 최신 날짜 그룹(latest_seqs)에 포함되지 않는 경우만 추출
            if lowest_seq not in latest_seqs:
                results.append({
                    "REQUEST_ID": rid,
                    "lowest_seq": lowest_seq,
                    "latest_seq": latest_seqs
                })
        
        return pd.DataFrame(results if results else {"REQUEST_ID": [], "lowest_seq": [], "latest_seq": []})
