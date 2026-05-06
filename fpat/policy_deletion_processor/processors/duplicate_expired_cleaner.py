#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
중복정책 중 모든 정책이 만료된 건을 분류하고 정리하는 모듈
"""

import logging
import pandas as pd
import os
import yaml
from datetime import datetime, timedelta
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

            # 4. 예외 대상 분류 (1): 모든 행이 '만료'인 중복 세트(No)
            def check_all_expired(group):
                return (group == '만료').all()

            expired_series = df_summary.groupby('No')['만료여부'].apply(check_all_expired)
            expired_nos = expired_series[expired_series].index.tolist()

            # 5. 예외 대상 분류 (2): 차단 정책 영향 분석 (하단최신정책 관련)
            # 5-1. 정책 파일에서 기초 정보 추출
            bottom_latest_req_ids = set(df_policy[df_policy['미사용여부'] == '하단최신정책']['REQUEST_ID'].dropna().unique())
            deny_seqs = sorted(df_policy[df_policy['Action'].str.lower() == 'deny']['Seq'].tolist())
            
            blocking_impact_nos = []
            
            # 5-2. '하단최신정책' 신청번호가 포함된 중복 세트(No) 추출
            potential_nos = df_summary[df_summary['Request ID'].isin(bottom_latest_req_ids)]['No'].unique()
            
            for no in potential_nos:
                group_df = df_summary[df_summary['No'] == no]
                
                # 삭제 대상 중 가장 상단(최소 Seq)과 유지 대상 중 가장 하단(최대 Seq) 추출
                delete_seqs = group_df[group_df['작업구분'] == '삭제']['Seq']
                keep_seqs = group_df[group_df['작업구분'] == '유지']['Seq']
                
                if not delete_seqs.empty and not keep_seqs.empty:
                    min_del_seq = delete_seqs.min()
                    max_keep_seq = keep_seqs.max()
                    
                    # 삭제되는 상단 정책과 유지되는 하단 정책 사이에 차단(deny) 정책이 있는지 확인
                    # 로직: min_del_seq < deny_seq < max_keep_seq
                    is_blocked = any(min_del_seq < s < max_keep_seq for s in deny_seqs)
                    
                    if is_blocked:
                        blocking_impact_nos.append(no)

            # 6. 최종 예외 No 합치기 및 사유 기입
            all_exception_nos = list(set(expired_nos + blocking_impact_nos))
            
            df_summary['비고'] = ''
            df_summary.loc[df_summary['No'].isin(expired_nos), '비고'] = '전체만료'
            df_summary.loc[df_summary['No'].isin(blocking_impact_nos), '비고'] = '차단영향위험'

            if not all_exception_nos:
                print("ℹ️ 예외 처리할 중복 세트가 없습니다.")
            else:
                print(f"✅ 총 {len(all_exception_nos)}개의 예외 세트를 발견했습니다.")
                if expired_nos: print(f"   - 전체만료: {len(expired_nos)}개")
                if blocking_impact_nos: print(f"   - 차단영향: {len(blocking_impact_nos)}개")

            # 7. 데이터 분리
            df_summary_main = df_summary[~df_summary['No'].isin(all_exception_nos)].copy()
            df_summary_exc = df_summary[df_summary['No'].isin(all_exception_nos)].copy()

            # 8. 공지 및 삭제 파일에서 해당 No 제거
            df_notice_new = df_notice[~df_notice['No'].isin(all_exception_nos)].copy()
            df_delete_new = df_delete[~df_delete['No'].isin(all_exception_nos)].copy()

            # 9. 파일 저장 (openpyxl 엔진 사용)
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

            # 10. 미사용 예외 데이터 추출 및 YAML 통합 관리 (개선)
            if '미사용예외' in df_summary.columns:
                unused_exc_df = df_summary[df_summary['미사용예외'] == True].copy()
                
                if not unused_exc_df.empty:
                    print("\n[예외 기록] 대상 방화벽명을 입력하세요 (예: FW_MAIN, PA_SEOUL):")
                    firewall_name = input(">> ").strip() or "Unknown_FW"
                    
                    current_time = datetime.now()
                    today_str = current_time.strftime('%Y-%m-%d')
                    expiry_str = (current_time + timedelta(days=90)).strftime('%Y-%m-%d')
                    
                    # 통합 YAML 파일 경로 (정리 파일과 동일한 디렉토리 또는 지정된 data 디렉토리)
                    yaml_path = os.path.join(os.path.dirname(summary_output), "duplicate_exceptions.yaml")
                    
                    # 기존 데이터 로드
                    all_exceptions = {}
                    if os.path.exists(yaml_path):
                        try:
                            with open(yaml_path, 'r', encoding='utf-8') as f:
                                all_exceptions = yaml.safe_load(f) or {}
                        except Exception as e:
                            logger.warning(f"기존 YAML 로드 실패: {e}")

                    # 해당 방화벽의 기존 예외 리스트 가져오기 (없으면 생성)
                    if firewall_name not in all_exceptions:
                        all_exceptions[firewall_name] = []
                    
                    # 신규 예외 추가 및 업데이트
                    existing_policy_names = {p['name']: i for i, p in enumerate(all_exceptions[firewall_name])}
                    
                    new_count = 0
                    update_count = 0
                    
                    for rule_name in unused_exc_df['Rule Name'].unique():
                        rule_name_str = str(rule_name)
                        new_entry = {
                            'name': rule_name_str,
                            'reason': '중복정책삭제_하단노출_임시예외',
                            'registered_at': today_str,
                            'expires_at': expiry_str
                        }
                        
                        if rule_name_str in existing_policy_names:
                            # 기존 항목 업데이트
                            idx = existing_policy_names[rule_name_str]
                            all_exceptions[firewall_name][idx] = new_entry
                            update_count += 1
                        else:
                            # 신규 항목 추가
                            all_exceptions[firewall_name].append(new_entry)
                            new_count += 1
                    
                    # YAML 저장
                    with open(yaml_path, 'w', encoding='utf-8') as f:
                        yaml.dump(all_exceptions, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
                    
                    print(f"✅ 중복정책 미사용 예외 통합 관리 파일 업데이트 완료!")
                    print(f"   - 파일경로: {yaml_path}")
                    print(f"   - 방화벽: {firewall_name} (신규: {new_count}, 갱신: {update_count})")

            print(f"\n✨ 작업 완료!")
            print(f"- 정리파일(시트분리): {summary_output}")
            print(f"- 공지파일(필터링): {notice_output}")
            print(f"- 삭제파일(필터링): {delete_output}")

            return True

        except Exception as e:
            logger.exception(f"중복 만료정책 정리 중 오류 발생: {e}")
            print(f"❌ 오류 발생: {e}")
            return False
