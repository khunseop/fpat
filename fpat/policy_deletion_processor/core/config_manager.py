#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
설정 파일을 관리하는 모듈 (YAML/JSON 지원)
"""

import json
import logging
import sys
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger(__name__)

class ConfigManager:
    """FPAT 통합 설정 관리자"""
    
    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        설정 관리자를 초기화합니다.
        
        탐색 순서:
        1. config_path (명시적 경로)
        2. FPAT_CONFIG 환경 변수
        3. 현재 작업 디렉토리의 fpat.yaml 또는 config.json
        4. 패키지 내의 기본 설정 파일
        """
        self.config_path = self._find_config(config_path)
        self.config_data = self._load_config()
        logger.info(f"설정 파일을 로드했습니다: {self.config_path}")

    def _get_package_base_dir(self) -> str:
        """패키지 설치 경로 반환"""
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    def _find_config(self, explicit_path: Optional[str]) -> str:
        """설정 파일의 유효한 경로를 탐색합니다."""
        search_paths = []
        
        # 1. 명시적 경로
        if explicit_path:
            search_paths.append(explicit_path)
            
        # 2. 환경 변수
        env_path = os.environ.get('FPAT_CONFIG')
        if env_path:
            search_paths.append(env_path)
            
        # 3. 현재 작업 디렉토리
        cwd = os.getcwd()
        search_paths.append(os.path.join(cwd, 'fpat.yaml'))
        search_paths.append(os.path.join(cwd, 'fpat.yml'))
        search_paths.append(os.path.join(cwd, 'config.json'))
        
        # 4. 패키지 기본 위치
        pkg_dir = self._get_package_base_dir()
        search_paths.append(os.path.join(pkg_dir, 'fpat.yaml'))
        search_paths.append(os.path.join(pkg_dir, 'config.json'))

        for path in search_paths:
            if os.path.exists(path) and os.path.isfile(path):
                return path
                
        # 기본값 (파일이 없어도 경로만 반환하여 로드 시 에러 처리하게 함)
        return os.path.join(cwd, 'fpat.yaml')

    def _load_config(self) -> Dict[str, Any]:
        """파일 확장자에 따라 설정을 로드합니다."""
        if not os.path.exists(self.config_path):
            logger.warning(f"설정 파일을 찾을 수 없습니다: {self.config_path}. 기본값을 사용합니다.")
            return {}

        try:
            _, ext = os.path.splitext(self.config_path)
            ext = ext.lower()
            
            if ext in ['.yaml', '.yml']:
                if not HAS_YAML:
                    raise ImportError("YAML 파일을 로드하려면 'PyYAML' 라이브러리가 필요합니다.")
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return yaml.safe_load(f) or {}
            else:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f) or {}
        except Exception as e:
            logger.error(f"설정 파일 로드 실패 ({self.config_path}): {e}")
            return {}

    def get(self, key: str, default: Any = None) -> Any:
        """
        설정값을 가져옵니다 (계층 구조 지원).
        예: config.get('exceptions.request_ids')
        """
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else:
                    raise KeyError
            return value
        except (KeyError, TypeError):
            return default 

    def is_excepted(self, category: str, value: str) -> bool:
        """
        특정 항목이 현재 예외 대상인지 확인합니다 (기간 만료 체크 포함).
        
        Args:
            category: 'request_ids' 또는 'policy_rules'
            value: 체크할 ID 또는 Rule Name
            
        Returns:
            bool: 예외 대상 여부
        """
        exceptions = self.get(f'exceptions.{category}', [])
        current_date = datetime.now().date()
        
        for item in exceptions:
            match = False
            # 1. 매칭 방식 결정
            if category == 'request_ids':
                target_id = item.get('id', '')
                if value == target_id:
                    match = True
            elif category == 'policy_rules':
                pattern = item.get('pattern', '')
                if re.match(pattern, value):
                    match = True
            
            # 2. 매칭된 경우 기간 체크
            if match:
                until_str = item.get('until')
                if not until_str:
                    return True # 영구 예외
                
                try:
                    until_date = datetime.strptime(until_str, '%Y-%m-%d').date()
                    if until_date >= current_date:
                        return True # 아직 유효한 예외
                    else:
                        logger.debug(f"예외 기간 만료됨: {value} (until: {until_str})")
                except ValueError:
                    logger.warning(f"잘못된 날짜 형식 (until): {until_str}")
                    return True # 형식 오류 시 안전을 위해 예외 유지
                    
        # 3. 정적 리스트 체크 (호환성용)
        static_list = self.get('exceptions.static_list', [])
        if value in static_list:
            return True
            
        return False

    def all(self) -> Dict[str, Any]:
        return self.config_data
