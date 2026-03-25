import pandas as pd
from typing import Tuple, Dict

class PolicyResolver:
    def __init__(self):
        self.cache: Dict[str, Tuple[str, str, str, str]] = {}

    def resolve_groupname_to_entry(self, name: str, network_group_dict: dict, resolved_cache: dict, depth: int = 0, max_depth: int = 10) -> str:
        if depth > max_depth or name in resolved_cache:
            return resolved_cache.get(name, name)

        entry = network_group_dict.get(name)
        if entry and entry != name:
            resolved_entries = [self.resolve_groupname_to_entry(n.strip(), network_group_dict, resolved_cache, depth + 1) for n in entry.split(',')]
            resolved_name = ','.join(set(resolved_entries))
            resolved_cache[name] = resolved_name
            return resolved_name

        resolved_cache[name] = name
        return name

    def process_cell(self, cell: str, network_group_dict: dict) -> str:
        resolved_cache = {}
        names = [name.strip() for name in str(cell).split(',')]
        resolved_names = [self.resolve_groupname_to_entry(name, network_group_dict, resolved_cache) for name in names]
        flattened_resolved = set(','.join(resolved_names).split(','))
        return ','.join(flattened_resolved)

    def replace_object_to_value(self, resolved_source: str, network_dict: dict) -> str:
        replaced_names = [str(network_dict.get(name, name)) for name in str(resolved_source).split(',')]
        return ','.join(set(replaced_names))


    def combine_protocol_port(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Protocol + Port 정보를 기반으로 Value 컬럼 생성
        - Protocol은 항상 대문자로 변환
        - Port에 *은 '0-65535'로 처리
        - Port에 ,가 있을 경우 row 분리

        Args:
            df (pd.DataFrame): 'Name', 'Protocol', 'Port' 컬럼 포함한 DataFrame

        Returns:
            pd.DataFrame: 'Value' 컬럼 추가 및 필요시 row 분리된 DataFrame
        """
        rows = []

        for _, row in df.iterrows():
            name = row['Name']
            protocol = str(row['Protocol']).upper()
            port_raw = str(row['Port']).replace(' ', '')

            # '*' 처리 → '0-65535'
            if port_raw == '*':
                ports = ['0-65535']
            else:
                ports = port_raw.split(',')

            for port in ports:
                port = port.strip()
                value = f"{protocol}/{port}"
                rows.append({'Name': name, 'Protocol': protocol, 'Port': port, 'Value': value})

        return pd.DataFrame(rows)

    def resolve(self, rules_df: pd.DataFrame, address_df: pd.DataFrame, addr_group_df: pd.DataFrame, 
                service_df: pd.DataFrame, svc_group_df: pd.DataFrame, rule_type: str = 'security') -> pd.DataFrame:
        """
        추출된 모든 객체 정보를 바탕으로 정책 내의 이름을 실제 값으로 해소합니다.
        
        Args:
            rules_df: 보안 또는 NAT 정책 DataFrame
            address_df: 주소 객체 DataFrame (Name, Type, Value)
            addr_group_df: 주소 그룹 DataFrame (Group Name, Entry)
            service_df: 서비스 객체 DataFrame (Name, Protocol, Port)
            svc_group_df: 서비스 그룹 DataFrame (Group Name, Entry)
            rule_type: 'security' 또는 'nat'
        """
        try:
            # 1. 룩업 딕셔너리 준비
            network_group_dict = addr_group_df.set_index('Group Name')['Entry'].to_dict() if not addr_group_df.empty else {}
            network_dict = address_df.set_index('Name')['Value'].to_dict() if not address_df.empty else {}

            if svc_group_df is None or svc_group_df.empty:
                svc_group_df = pd.DataFrame(columns=['Group Name', 'Entry'])
            service_group_dict = svc_group_df.set_index('Group Name')['Entry'].to_dict()

            # 서비스 객체는 Protocol/Port를 결합한 Value 컬럼이 필요함
            if not service_df.empty and 'Value' not in service_df.columns:
                service_df_combined = self.combine_protocol_port(service_df)
                service_dict = service_df_combined.set_index('Name')['Value'].to_dict()
            else:
                service_dict = service_df.set_index('Name')['Value'].to_dict() if not service_df.empty else {}
            
            # 2. 정책 타입별 해석 실행
            if rule_type == "security":
                # 그룹 해소 (재귀)
                rules_df['Resolved Source'] = rules_df['Source'].apply(lambda x: self.process_cell(x, network_group_dict))
                rules_df['Resolved Destination'] = rules_df['Destination'].apply(lambda x: self.process_cell(x, network_group_dict))
                rules_df['Resolved Service'] = rules_df['Service'].apply(lambda x: self.process_cell(x, service_group_dict))

                # 실제 값으로 치환
                rules_df['Extracted Source'] = rules_df['Resolved Source'].apply(lambda x: self.replace_object_to_value(x, network_dict))
                rules_df['Extracted Destination'] = rules_df['Resolved Destination'].apply(lambda x: self.replace_object_to_value(x, network_dict))
                rules_df['Extracted Service'] = rules_df['Resolved Service'].apply(lambda x: self.replace_object_to_value(x, service_dict))
 
                rules_df.drop(columns=['Resolved Source', 'Resolved Destination', 'Resolved Service'], inplace=True)

            elif rule_type == "nat":
                # NAT 정책 컬럼 해석
                src_col = 'Original Packet Source Address'
                dst_col = 'Original Packet Destination Address'
                svc_col = 'Original Packet Service'
                ts_src_col = 'Translated Packet Source Translation'
                ts_dst_col = 'Translated Packet Destination Translation'

                for col, dict_map, prefix in [
                    (src_col, network_group_dict, 'Resolved OG Source'),
                    (dst_col, network_group_dict, 'Resolved OG Destination'),
                    (svc_col, service_group_dict, 'Resolved OG Service'),
                    (ts_src_col, network_group_dict, 'Resolved TS Source'),
                    (ts_dst_col, network_group_dict, 'Resolved TS Destination')
                ]:
                    if col in rules_df.columns:
                        rules_df[prefix] = rules_df[col].apply(lambda x: self.process_cell(x, dict_map))

                # 값 치환
                val_maps = [
                    ('Resolved OG Source', network_dict, 'Extracted OG Source'),
                    ('Resolved OG Destination', network_dict, 'Extracted OG Destination'),
                    ('Resolved OG Service', service_dict, 'Extracted OG Service'),
                    ('Resolved TS Source', network_dict, 'Extracted TS Source'),
                    ('Resolved TS Destination', network_dict, 'Extracted TS Destination')
                ]

                for res_col, v_map, ext_col in val_maps:
                    if res_col in rules_df.columns:
                        rules_df[ext_col] = rules_df[res_col].apply(lambda x: self.replace_object_to_value(x, v_map))
                        rules_df.drop(columns=[res_col], inplace=True)
            
            return rules_df
        except Exception as e:
            self.logger.error(f"데이터 처리 중 오류 발생: {e}")
            return pd.DataFrame()
