#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FPAT으로 추출된 Hit 정보 2개를 Merge하는 모듈
"""

import logging
import pandas as pd

from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class MergeHitcount(BaseProcessor):
    """FPAT으로 추출된 Hit 정보 2개를 Merge하는 클래스"""
    
    def run(self, file_manager, **kwargs):
        """Hit 정보 2개를 Merge합니다."""
        return self.mergehitcounts(file_manager)
    
    def _load_usage_df(self, file_path):
        """엑셀 파일에서 사용이력 데이터를 스마트하게 로드합니다."""
        try:
            xls = pd.ExcelFile(file_path)
            # 'usage' 시트가 있으면 해당 시트 사용, 없으면 첫 번째(index 0) 시트 사용
            sheet_name = 'usage' if 'usage' in xls.sheet_names else 0
            df = pd.read_excel(xls, sheet_name=sheet_name)
            
            if df.empty:
                logger.warning(f"파일 {file_path}의 '{sheet_name}' 시트가 비어있습니다.")
            else:
                logger.info(f"파일 {file_path}에서 '{sheet_name}' 시트를 로드했습니다. (레코드: {len(df)}개)")
            
            return df
        except Exception as e:
            logger.error(f"파일 로드 중 오류 발생 ({file_path}): {e}")
            return pd.DataFrame()

    def mergehitcounts(self, file_manager):
        """
        Hit 정보 2개를 Merge합니다.
        
        Args:
            file_manager: 파일 관리자
            
        Returns:
            bool: 성공 여부
        """
        try:
            print("첫 번째 Hit 파일을 선택하세요 (Primary 또는 Full Export):")
            first_file = file_manager.select_files()
            if not first_file:
                return False

            print("두 번째 Hit 파일을 선택하세요 (Secondary 사용이력):")
            second_file = file_manager.select_files()
            if not second_file:
                return False

            # 스마트 로딩 적용
            df1 = self._load_usage_df(first_file)
            df2 = self._load_usage_df(second_file)

            if df1.empty or df2.empty:
                logger.error("병합할 데이터가 부족합니다.")
                return False

            # 필수 컬럼 존재 여부 확인
            required_cols = ['Rule Name', 'Last Hit Date', 'Unused Days']
            for df_tmp, name in [(df1, "첫 번째"), (df2, "두 번째")]:
                missing = [col for col in required_cols if col not in df_tmp.columns]
                if missing:
                    logger.error(f"{name} 파일에 필수 컬럼이 누락되었습니다: {missing}")
                    return False

            # Rule Name을 기준으로 두 데이터프레임을 병합
            merged_df = pd.merge(df1, df2, on='Rule Name', suffixes=('_df1', '_df2'))

            if merged_df.empty:
                logger.warning("병합된 데이터가 없습니다. Rule Name이 일치하는지 확인하세요.")
                return False

            # 데이터 병합 로직
            # Vsys는 첫 번째 파일 기준 (보통 동일함)
            if 'Vsys_df1' in merged_df.columns:
                merged_df['Vsys'] = merged_df['Vsys_df1']
            
            # Hit Count 합산 (컬럼이 있는 경우만)
            if 'Hit Count_df1' in merged_df.columns and 'Hit Count_df2' in merged_df.columns:
                merged_df['Hit Count'] = merged_df['Hit Count_df1'] + merged_df['Hit Count_df2']
            
            # Last Hit Date는 더 최근 날짜(Max), Unused Days는 더 적은 일수(Min)
            merged_df['Last Hit Date'] = merged_df[['Last Hit Date_df1', 'Last Hit Date_df2']].max(axis=1)
            merged_df['Unused Days'] = merged_df[['Unused Days_df1', 'Unused Days_df2']].min(axis=1)
            
            # 병합 후 중복/임시 컬럼 제거
            cols_to_drop = [c for c in merged_df.columns if '_df1' in c or '_df2' in c]
            merged_df.drop(columns=cols_to_drop, inplace=True)
            
            # 90일 기준에 따라 '미사용여부' 컬럼 생성/갱신
            merged_df['미사용여부'] = merged_df['Unused Days'].apply(lambda x: '미사용' if x > 90 else '사용')
            
            # 엑셀 파일로 결과 저장 (표준 포맷 적용)
            import os
            from datetime import datetime
            today = datetime.now().strftime('%Y-%m-%d')
            
            # 첫 번째 파일명에서 IP 추출 시도
            filename = os.path.basename(first_file)
            parts = filename.split('_')
            ip_part = parts[1] if len(parts) > 1 else 'unknown'
            
            if not os.path.exists("outputs"):
                os.makedirs("outputs")
            output_excel_file = os.path.join("outputs", f"{today}_{ip_part}_merged.xlsx")
            
            merged_df.to_excel(output_excel_file, index=False)

            logger.info(f"병합 완료: {len(merged_df)}개 규칙 정보를 '{output_excel_file}'에 저장했습니다.")
            print(f"데이터를 {output_excel_file} 파일로 저장했습니다.")
            
            # 다음 단계를 위해 결과 파일 등록
            file_manager.set_forced_files([output_excel_excel_file if 'output_excel_excel_file' in locals() else output_excel_file])
            return True
        except Exception as e:
            logger.exception(f"Merge 중 오류 발생: {e}")
            return False 