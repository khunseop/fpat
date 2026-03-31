# firewall/paloalto/paloalto_collector.py
import pandas as pd
import datetime
from typing import Optional, Union
from ..firewall_interface import FirewallInterface
from .paloalto_module import PaloAltoAPI

from ..exceptions import (
    FirewallConnectionError, 
    FirewallAPIError
)


class PaloAltoCollector(FirewallInterface):
    def __init__(self, hostname: str, username: str, password: str):
        super().__init__(hostname, username, password)
        self.api = PaloAltoAPI(hostname, username, password)

    def connect(self) -> bool:
        """방화벽 연결 테스트 및 상태 갱신"""
        try:
            self.api.get_system_info()
            self._connected = True
            return True
        except Exception as e:
            self._connected = False
            raise FirewallConnectionError(f"PaloAlto 연결 실패: {e}") from e

    def disconnect(self) -> bool:
        """연결 해제"""
        self._connected = False
        return True

    def test_connection(self) -> bool:
        """연결 가능 여부 확인"""
        try:
            self.api.get_system_info()
            return True
        except Exception:
            return False

    def get_system_info(self) -> pd.DataFrame:
        """시스템 정보를 반환합니다."""
        return self.api.get_system_info()

    def export_security_rules(self, config_type: str = "running") -> pd.DataFrame:
        """
        보안 규칙을 반환합니다.
        """
        return self.api.export_security_rules(config_type=config_type)

    def export_network_objects(self) -> pd.DataFrame:
        """네트워크 객체 정보를 반환합니다."""
        return self.api.export_network_objects()

    def export_network_group_objects(self) -> pd.DataFrame:
        """네트워크 그룹 객체 정보를 반환합니다."""
        return self.api.export_network_group_objects()

    def export_service_objects(self) -> pd.DataFrame:
        """서비스 객체 정보를 반환합니다."""
        return self.api.export_service_objects()

    def export_service_group_objects(self) -> pd.DataFrame:
        """서비스 그룹 객체 정보를 반환합니다."""
        return self.api.export_service_group_objects()
    
    def export_usage_logs(self, days: Optional[int] = 90, use_ssh: bool = False) -> pd.DataFrame:
        """정책 사용이력을 DataFrame으로 반환합니다.
        
        Args:
            days: 미사용 기준 일수
            use_ssh: True면 SSH 방식을 사용 (API 타임아웃 발생 시 권장)
        """
        if use_ssh:
            # SSH를 통해 수집
            result_df = self.export_last_hit_date_ssh()
            if result_df.empty:
                return result_df
            
            # Unused Days 계산
            current_date = datetime.datetime.now()
            def calc_days(last_date_str):
                if not last_date_str: return 99999
                try:
                    dt = datetime.datetime.strptime(last_date_str, '%Y-%m-%d %H:%M:%S')
                    return (current_date - dt).days
                except: return 99999
            
            result_df['Unused Days'] = result_df['Last Hit Date'].apply(calc_days)
        else:
            # 기존 API 방식으로 수집
            vsys_list = self.api.get_vsys_list()
            hit_counts = []
            for vsys in vsys_list:
                df = self.api.export_hit_count(vsys)
                hit_counts.append(df)
            result_df = pd.concat(hit_counts, ignore_index=True)
        
        # 미사용여부 컬럼 추가 (공통)
        def determine_usage_status(unused_days):
            if pd.isna(unused_days):
                return '미사용'
            if days is not None and unused_days > days:
                return '미사용'
            return '사용'
        
        result_df['미사용여부'] = result_df['Unused Days'].apply(determine_usage_status)
        
        return result_df

    def export_last_hit_date_ssh(self, vsys: Union[list, set, None] = None) -> pd.DataFrame:
        """
        SSH를 통해 각 규칙의 최근 히트 일자 정보를 수집합니다.
        로직은 PaloAltoAPI로 위임되었습니다.
        """
        return self.api.export_last_hit_date_ssh(vsys)
