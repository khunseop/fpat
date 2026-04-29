#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
중복정책 중 모든 정책이 만료된 건을 분류하고 정리하는 모듈
"""

import logging
import pandas as pd
from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class DuplicateExpiredCleaner(BaseProcessor):
    """중복정책 중 만료 건을 자동으로 정리하는 클래스"""

    def run(self, file_manager, **kwargs):
        """만료된 중복정책 세트를 분류하고 파일들을 업데이트합니다."""
        try:
            # 1. 파일 선택
            print("\n[파일 선택 순서: 정책원본 -> 중복정리 -> 중복공지 -> 중복삭제]")
            
            print("1/4. '만료여부'가 포함된 정책 원본 파일을 선택하세요:")
            policy_file = file_manager.select_files()
            if not policy_file: return False
            
            print("2/4. 중복정책 '정리' 파일을 선택하세요:")
            summary_file = file_manager.select_files()
            if not summary_file: return False
            
            print("3/4. 중복정책 '공지' 파일을 선택하세요:")
            notice_file = file_manager.select_files()
            if not notice_file: return False
            
            print("4/4. 중복정책 '삭제' 파일을 선택하세요:")
            delete_file = file_manager.select_files()
            if not delete_file: return False

            # 2. 데이터 로드
            df_policy = pd.read_excel(policy_file)
            df_summary = pd.read_excel(summary_file)
            df_notice = pd.read_excel(notice_file)
            df_delete = pd.read_excel(delete_file)

            # 3. 만료여부 매핑
            if '만료여부' not in df_policy.columns:
                print("❌ 정책 원본 파일에 '만료여부' 컬럼이 없습니다.")
                return False
            
            # Rule Name 기준으로 만료여부 맵 생성
            expiry_map = df_policy.set_index('Rule Name')['만료여부'].to_dict()
            df_summary['만료여부'] = df_summary['Rule Name'].map(expiry_map).fillna('확인필요')

            # 4. 모든 행이 '만료'인 중복 세트(No) 찾기
            # 'No'별로 그룹화하여 모든 '만료여부'가 '만료'인 그룹의 No 목록 추출
            def check_all_expired(group):
                return (group == '만료').all()

            expired_series = df_summary.groupby('No')['만료여부'].apply(check_all_expired)
            expired_nos = expired_series[expired_series].index.tolist()

            if not expired_nos:
                print("ℹ️ 모든 정책이 '만료'인 중복 세트가 없습니다.")
            else:
                print(f"✅ 총 {len(expired_nos)}개의 만료 세트를 발견했습니다. (No: {expired_nos})")

            # 5. 중복 정리 파일 처리 (메인 시트에서 제거 및 예외 시트로 이동)
            df_summary_main = df_summary[~df_summary['No'].isin(expired_nos)].copy()
            df_summary_exc = df_summary[df_summary['No'].isin(expired_nos)].copy()

            # 6. 공지 및 삭제 파일에서 해당 No 제거
            df_notice_new = df_notice[~df_notice['No'].isin(expired_nos)].copy()
            df_delete_new = df_delete[~df_delete['No'].isin(expired_nos)].copy()

            # 7. 파일 저장 (openpyxl 엔진 사용)
            # 정리 파일 (두 개의 시트로 저장)
            summary_output = file_manager.update_version(summary_file, False)
            with pd.ExcelWriter(summary_output, engine='openpyxl') as writer:
                df_summary_main.to_excel(writer, sheet_name='중복정책정리', index=False)
                df_summary_exc.to_excel(writer, sheet_name='예외', index=False)

            # 공지 및 삭제 파일
            notice_output = file_manager.update_version(notice_file, False)
            df_notice_new.to_excel(notice_output, index=False, engine='openpyxl')

            delete_output = file_manager.update_version(delete_file, False)
            df_delete_new.to_excel(delete_output, index=False, engine='openpyxl')

            print(f"\n✨ 작업 완료!")
            print(f"- 정리파일(시트분리): {summary_output}")
            print(f"- 공지파일(필터링): {notice_output}")
            print(f"- 삭제파일(필터링): {delete_output}")

            return True

        except Exception as e:
            logger.exception(f"중복 만료정책 정리 중 오류 발생: {e}")
            print(f"❌ 오류 발생: {e}")
            return False
