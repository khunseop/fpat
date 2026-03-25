"""
중복 정책 분석을 위한 클래스입니다.
"""

import pandas as pd
import logging
import ipaddress
from typing import Dict, List, Tuple, Set, Union, Optional
from collections import defaultdict

class RedundancyAnalyzer:
    """중복 정책 분석을 위한 클래스"""
    
    def __init__(self):
        """RedundancyAnalyzer 초기화"""
        self.logger = logging.getLogger(__name__)
        self.vendor_columns = {
            'paloalto': ['Enable', 'Action', 'Source', 'User', 'Destination', 'Service', 'Application', 'Security Profile','Category', 'Vsys'],
            'ngf': ['Enable', 'Action', 'Source', 'User', 'Destination', 'Service', 'Application'],
            'default': ['Enable', 'Action', 'Source', 'User', 'Destination', 'Service', 'Application']
        }
        self.extracted_columns = {
            'paloalto': ['Enable', 'Action', 'Extracted Source', 'User', 'Extracted Destination', 'Extracted Service', 'Application', 'Security Profile', 'Category', 'Vsys'],
            'ngf': ['Enable', 'Action', 'Extracted Source', 'User', 'Extracted Destination', 'Extracted Service', 'Application'],
            'default': ['Enable', 'Action', 'Extracted Source', 'User', 'Extracted Destination', 'Extracted Service', 'Application']
        }

    def _parse_ip_entities(self, ip_str: str) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """문자열 대역을 IP 네트워크 객체 리스트로 변환합니다."""
        entities = []
        for part in str(ip_str).split(','):
            part = part.strip()
            if not part or part.lower() in ['any', 'any4', 'any6']:
                continue
            try:
                if '-' in part: # 범위 처리
                    start_ip, end_ip = part.split('-')
                    nets = list(ipaddress.summarize_address_range(
                        ipaddress.ip_address(start_ip.strip()),
                        ipaddress.ip_address(end_ip.strip())
                    ))
                    entities.extend(nets)
                else: # CIDR 또는 단일 IP
                    entities.append(ipaddress.ip_network(part, strict=False))
            except:
                continue
        return entities

    def _is_contained(self, small_val: str, large_val: str, mode: str = 'ip') -> bool:
        """small_val의 모든 요소가 large_val에 포함되는지 확인합니다."""
        l_val_str = str(large_val).lower()
        s_val_str = str(small_val).lower()
        
        if l_val_str in ['any', 'any4', 'any6', 'all']:
            return True
        if s_val_str in ['any', 'any4', 'any6', 'all']:
            return False
            
        if mode == 'ip':
            small_nets = self._parse_ip_entities(small_val)
            large_nets = self._parse_ip_entities(large_val)
            
            if not small_nets: return False
            if not large_nets: return False
            
            for s_net in small_nets:
                found = False
                for l_net in large_nets:
                    if l_net.supernet_of(s_net):
                        found = True
                        break
                if not found: return False
            return True
            
        elif mode == 'port':
            s_set = set(str(small_val).replace(' ', '').split(','))
            l_set = set(str(large_val).replace(' ', '').split(','))
            return s_set.issubset(l_set)
            
        return False

    def analyze_logical(self, df: pd.DataFrame, vendor: str = 'default') -> pd.DataFrame:
        """
        치환된 값을 기반으로 논리적 포함 관계를 분석하여 중복 정책을 찾아냅니다.
        """
        try:
            self.logger.info("논리적 중복 분석(Logical Analysis) 시작")
            
            required_cols = ['Extracted Source', 'Extracted Destination', 'Extracted Service', 'Action', 'Enable']
            if not all(col in df.columns for col in required_cols):
                self.logger.warning("논리 분석을 위한 컬럼이 누락되어 일반 텍스트 분석을 수행합니다.")
                return self.analyze(df, vendor)

            # 활성 Allow 정책만 대상
            df_active = df[(df['Enable'] == 'Y') & (df['Action'] == 'allow')].copy()
            total = len(df_active)
            results_list = []
            policy_map = {} 
            current_no = 1

            for i in range(total):
                target_row = df_active.iloc[i]
                for j in range(i):
                    base_row = df_active.iloc[j]
                    
                    if (self._is_contained(target_row['Extracted Source'], base_row['Extracted Source'], 'ip') and
                        self._is_contained(target_row['Extracted Destination'], base_row['Extracted Destination'], 'ip') and
                        self._is_contained(target_row['Extracted Service'], base_row['Extracted Service'], 'port')):
                        
                        group_no = policy_map.get(j, current_no)
                        if j not in policy_map:
                            policy_map[j] = group_no
                            u_row = df_active.iloc[j].to_dict()
                            u_row.update({'No': group_no, 'Type': 'Upper'})
                            results_list.append(u_row)
                            current_no += 1
                        
                        l_row = target_row.to_dict()
                        l_row.update({'No': group_no, 'Type': 'Lower'})
                        results_list.append(l_row)
                        policy_map[i] = group_no
                        break
                
                if i % max(1, total // 10) == 0:
                    print(f"\r논리 분석 진행 중: {(i+1)/total*100:.1f}%", end='', flush=True)

            print()
            if not results_list:
                return pd.DataFrame(columns=['No', 'Type'] + list(df.columns))

            res_df = pd.DataFrame(results_list).drop_duplicates(subset=['No', 'Type', 'Rule Name'])
            res_df = res_df.sort_values(by=['No', 'Type'], ascending=[True, False])
            cols = ['No', 'Type'] + [c for c in df.columns if c not in ['No', 'Type']]
            return res_df[cols]

        except Exception as e:
            self.logger.error(f"논리 분석 중 오류 발생: {e}")
            return df

    def _normalize_policy(self, policy_series: pd.Series) -> tuple:
        """정책 데이터를 정규화합니다."""
        normalized_policy = policy_series.apply(lambda x: ','.join(sorted(x.split(','))) if isinstance(x, str) else x)
        return tuple(normalized_policy)
    
    def _prepare_data(self, df: pd.DataFrame, vendor: str) -> pd.DataFrame:
        """분석을 위해 데이터를 준비합니다."""
        df_filtered = df[(df['Enable'] == 'Y') & (df['Action'] == 'allow')].copy()
        if vendor == 'paloalto':
            df_filtered['Service'] = df_filtered['Service'].str.replace('_', '-')
        return df_filtered
    
    def analyze(self, df: pd.DataFrame, vendor: str, **kwargs) -> pd.DataFrame:
        """텍스트 기반의 기본 중복 정책을 분석합니다."""
        try:
            self.logger.info("기본 중복 정책 분석 시작")
            df_filtered = self._prepare_data(df, vendor)
            
            if 'Extracted Source' in df_filtered.columns:
                columns_to_check = self.extracted_columns.get(vendor, self.extracted_columns['default'])
            else:
                columns_to_check = self.vendor_columns.get(vendor, self.vendor_columns['default'])

            df_check = df_filtered[columns_to_check]
            policy_map = defaultdict(list)
            results_list = []
            current_no = 1
            total = len(df_filtered)
            
            for i in range(total):
                current_policy = self._normalize_policy(df_check.iloc[i])
                if current_policy in policy_map:
                    row = df_filtered.iloc[i].to_dict()
                    row.update({'No': policy_map[current_policy], 'Type': 'Lower'})
                    results_list.append(row)
                else:
                    policy_map[current_policy] = current_no
                    row = df_filtered.iloc[i].to_dict()
                    row.update({'No': current_no, 'Type': 'Upper'})
                    results_list.append(row)
                    current_no += 1
            
            results = pd.DataFrame(results_list)
            if results.empty: return results

            def ensure_upper_and_lower(df_res):
                valid_no_groups = []
                for name, group in df_res.groupby('No'):
                    if 'Upper' in group['Type'].values and 'Lower' in group['Type'].values:
                        valid_no_groups.append(group)
                return pd.concat(valid_no_groups).reset_index(drop=True) if valid_no_groups else pd.DataFrame(columns=df_res.columns)

            duplicated_results = ensure_upper_and_lower(results)
            if duplicated_results.empty:
                return pd.DataFrame(columns=['No', 'Type'] + list(df.columns))
            
            duplicated_results['No'] = duplicated_results.groupby('No').ngroup() + 1
            columns_order = ['No', 'Type'] + [col for col in df.columns]
            return duplicated_results[columns_order].sort_values(by=['No', 'Type'], ascending=[True, False])
            
        except Exception as e:
            self.logger.error(f"중복 정책 분석 중 오류 발생: {e}")
            raise
