"""
방화벽 정책 분석을 위한 모듈입니다.
이 모듈은 정책의 중복성, 변경사항, 사용현황 등을 분석하는 기능을 제공합니다.
"""

from .core.policy_analyzer import PolicyAnalyzer
from .core.redundancy_analyzer import RedundancyAnalyzer
from .core.change_analyzer import ChangeAnalyzer
from .core.policy_resolver import PolicyResolver
from .core.shadow_analyzer import ShadowAnalyzer
from .core.policy_filter import PolicyFilter
import pandas as pd

def run_integrated_analysis(collector, rule_type: str = 'security') -> pd.DataFrame:
    """
    방화벽 콜렉터로부터 데이터를 직접 추출하여 논리적 중복 분석을 수행합니다.
    """
    try:
        # 1. 전역 데이터 추출 (firewall_module 활용)
        if rule_type == 'security':
            rules = collector.export_security_rules()
        else:
            # NAT 지원 여부 확인
            if hasattr(collector, 'export_nat_rules'):
                rules = collector.export_nat_rules()
            else:
                print(f"로그: 해당 콜렉터({collector.__class__.__name__})는 NAT 추출을 지원하지 않습니다.")
                return pd.DataFrame()

        address_df = collector.export_network_objects()
        addr_group_df = collector.export_network_group_objects()
        service_df = collector.export_service_objects()
        svc_group_df = collector.export_service_group_objects()

        # 2. 객체 해소 (Resolver)
        resolver = PolicyResolver()
        resolved_rules = resolver.resolve(
            rules, 
            address_df, 
            addr_group_df, 
            service_df, 
            svc_group_df, 
            rule_type=rule_type
        )

        if resolved_rules.empty:
            return pd.DataFrame()

        # 3. 논리적 정밀 분석 실행 (RedundancyAnalyzer)
        analyzer = RedundancyAnalyzer()
        return analyzer.analyze_logical(resolved_rules)
    except Exception as e:
        import logging
        logging.error(f"통합 분석 중 예상치 못한 오류 발생: {e}")
        return pd.DataFrame()

__all__ = [
    'PolicyAnalyzer', 
    'RedundancyAnalyzer', 
    'ChangeAnalyzer', 
    'PolicyResolver', 
    'ShadowAnalyzer', 
    'PolicyFilter',
    'run_integrated_analysis'
]