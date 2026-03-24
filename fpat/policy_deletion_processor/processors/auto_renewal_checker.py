#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
제공받은 DB 취합본에서 같은 신청번호에서 기간이 1년 증가한 데이터를 확인
"""

import logging
import pandas as pd
import re

logger = logging.getLogger(__name__)

class AutoRenewalChecker:

    def __init__(self, config_manager):
        """
        Merge 모듈을 초기화합니다.

        Args:
            config_manager: 설정 관리자
        """
        self.config =config_manager
    
    def renewal_check(self, file_manager):
        """

        Args:
            file_manager: 파일 관리자
        
        Returns:
            bool: 성공 여부
        """
        def remove_bracket_prefix(text):
            if isinstance(text, str) and text.startswith('['):
                # 반복적으로 앞에서 괄호 안 문자열이 8자 이하일 때만 제거
                    while True:
                        match = re.match(r'^\[([^\[\]]{1,8})\]', text)
                        if match:
                            text = text[len(match.group(0)):] # 괄호 포함된 부분 제거
                        else:
                            break
            return text
        
        try:
            print("가공된 신청정보 파일을 선택하세요.")
            file_name = file_manager.select_files()
            if not file_name:
                return False
            
            df = pd.read_excel(file_name)

            # 날짜 형식으로 변환
            df['REQUEST_START_DATE'] = pd.to_datetime(df['REQUEST_START_DATE'])
            df['REQUEST_END_DATE'] = pd.to_datetime(df['REQUEST_END_DATE'])

            # self merge로 END_DATE == START_DATE 조건에 맞는 행 찾기
            merged = pd.merge(
                df, df,
                left_on=['REQUEST_ID', 'REQUEST_END_DATE'],
                right_on=['REQUEST_ID', 'REQUEST_START_DATE'],
                suffixes=('_prev', '_next')
            )

            # TITLE_prev, TITLE_next 정제 컬럼 생성
            merged['TITLE_prev_clean'] = merged['TITLE_prev'].apply(remove_bracket_prefix)
            merged['TITLE_next_clean'] = merged['TITLE_next'].apply(remove_bracket_prefix)

            merged = merged[merged['WRITE_PERSON_ID_prev'] == merged['WRITE_PERSON_ID_next']]
            filtered_df = merged[merged['TITLE_prev_clean'] == merged['TITLE_next_clean']]

            # 엑셀 파일로 결과 저장
            output_excel_file = f"auto_renewal_{file_name}"
            filtered_df.to_excel(output_excel_file, index=False)

            logger.info(f"데이터를 '{output_excel_file}' 파일로 저장했습니다.")
            print(f"데이터를 {output_excel_file} 파일로 저장했습니다.")

            return True
        except Exception as e:
            logger.exception(e)
            return False
