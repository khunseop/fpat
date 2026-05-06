#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
기록된 중복정책 미사용 예외 정보를 정책 파일에 반영하는 모듈
"""

import logging
import pandas as pd
import yaml
import os
from datetime import datetime
from .base_processor import BaseProcessor

logger = logging.getLogger(__name__)

class DuplicateExceptionApplier(BaseProcessor):
    """중복정책 미사용 예외를 자동으로 적용하는 클래스"""

    def run(self, file_manager, **kwargs):
        """YAML 파일에서 예외 목록을 읽어 정책 파일에 반영합니다."""
        try:
            # 1. 파일 선택
            print("정책 파일을 선택하세요:")
            policy_file = file_manager.select_files()
            if not policy_file: return False
            
            print("중복정책 예외 관리 파일(duplicate_exceptions.yaml)을 선택하세요:")
            yaml_file = file_manager.select_files(extension=['.yaml', '.yml'])
            if not yaml_file: return False

            # 2. 데이터 로드
            df_policy = pd.read_excel(policy_file)
            
            with open(yaml_file, 'r', encoding='utf-8') as f:
                all_exceptions = yaml.safe_load(f) or {}

            if not all_exceptions:
                print("ℹ️ YAML 파일에 기록된 예외 데이터가 없습니다.")
                return True

            # 3. 방화벽명 선택 및 필터링
            print("\n[방화벽 선택] 예외를 적용할 방화벽명을 입력하세요:")
            available_fws = list(all_exceptions.keys())
            print(f"등록된 방화벽: {', '.join(available_fws)}")
            firewall_name = input(">> ").strip()

            if firewall_name not in all_exceptions:
                print(f"❌ '{firewall_name}'에 해당하는 예외 데이터가 없습니다.")
                return False

            fw_exceptions = all_exceptions[firewall_name]
            current_date = datetime.now().date()
            
            # 유효한 예외 정책명 목록 추출 (만료되지 않았고, 오늘 등록된 건 제외)
            valid_exc_names = []
            for item in fw_exceptions:
                expires_at = datetime.strptime(item['expires_at'], '%Y-%m-%d').date()
                registered_at = datetime.strptime(item['registered_at'], '%Y-%m-%d').date()
                
                # 1. 만료일이 오늘 이후여야 함
                # 2. 등록일이 오늘이 아니어야 함 (작업 당일 발생한 예외는 다음 분석부터 반영)
                if expires_at >= current_date and registered_at < current_date:
                    valid_exc_names.append(item['name'])
                else:
                    if registered_at == current_date:
                        logger.info(f"당일 등록 예외 제외 (다음 분석 시 반영): {item['name']}")
                    else:
                        logger.info(f"만료된 예외 제외: {item['name']} (만료일: {item['expires_at']})")

            if not valid_exc_names:
                print("ℹ️ 유효기간 내에 있는 예외 정책이 없습니다.")
                return True

            # 4. 정책 파일 업데이트
            if '미사용여부' not in df_policy.columns:
                df_policy['미사용여부'] = ''

            # 'Rule Name'이 예외 목록에 있는 경우 '미사용여부' 업데이트
            mask = df_policy['Rule Name'].isin(valid_exc_names)
            df_policy.loc[mask, '미사용여부'] = '중복정책_미사용예외'
            
            updated_count = mask.sum()

            # 5. 결과 저장
            output_file = file_manager.update_version(policy_file, False)
            df_policy.to_excel(output_file, index=False, engine='openpyxl')

            print(f"\n✨ 예외 반영 완료!")
            print(f"- 적용된 정책 수: {updated_count}개")
            print(f"- 결과 파일: {output_file}")

            return True

        except Exception as e:
            logger.exception(f"중복정책 예외 반영 중 오류 발생: {e}")
            print(f"❌ 오류 발생: {e}")
            return False
