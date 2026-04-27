#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
파일 관리 기능을 제공하는 모듈
"""

import os
import re
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

class FileManager:
    """파일 관리 기능을 제공하는 클래스"""
    
    def __init__(self, config_manager):
        """
        파일 관리자를 초기화합니다.
        
        Args:
            config_manager: 설정 관리자
        """
        self.config = config_manager
        self._forced_files: List[str] = [] # CLI 등에서 미리 지정된 파일 리스트

    def set_forced_files(self, files: List[str]):
        """대화형 선택을 건너뛰고 반환할 파일 리스트를 설정합니다."""
        self._forced_files = files

    def update_version(self, filename, final_version=False):
        """
        파일 이름의 버전을 업데이트하고 outputs 폴더 경로를 반환합니다.
        """
        # 기존 경로 정보 제거하고 파일명만 추출
        pure_filename = os.path.basename(filename)
        base_name, ext = pure_filename.rsplit('.', 1)
        
        version_format = self.config.get('file_management.policy_version_format', '_v{version}')
        final_suffix = self.config.get('file_management.final_version_suffix', '_vf')
        
        match = re.search(r'_v(\d+)$', base_name)
        final_match = re.search(r'_vf$', base_name)
        
        if final_version:
            if match:
                new_base_name = re.sub(r'_v\d+$', final_suffix, base_name)
            else:
                new_base_name = f"{base_name}{final_suffix}"
        else:
            if match:
                version = int(match.group(1))
                new_version = version + 1
                new_base_name = re.sub(r'_v\d+$', version_format.format(version=new_version), base_name)
            else:
                new_base_name = f"{base_name}{version_format.format(version=1)}"
        
        # 항상 outputs 폴더에 저장
        if not os.path.exists("outputs"):
            os.makedirs("outputs")
            
        new_filename = os.path.join("outputs", f"{new_base_name}.{ext}")
        logger.info(f"결과 파일 경로: {new_filename}")
        return new_filename
    
    def select_files(self, extension=None):
        """
        지정된 확장자의 파일 목록에서 파일을 선택합니다.
        CLI 모드에서 파일이 강제 지정된 경우 해당 파일을 우선 반환합니다.
        """
        # 1. 강제 지정된 파일이 있는 경우 순차적으로 반환
        if self._forced_files:
            selected = self._forced_files.pop(0)
            logger.info(f"강제 지정된 파일 선택: {selected}")
            return selected

        # 2. 대화형 선택 (기존 로직)
        if extension is None:
            extension = self.config.get('file_management.default_extension', '.xlsx')
            
        file_list = [file for file in os.listdir() if file.endswith(extension)]
        if not file_list:
            print(f"{extension} 확장자를 가진 파일이 없습니다.")
            return None
        
        for i, file in enumerate(file_list, start=1):
            print(f"{i}. {file}")
        
        while True:
            try:
                choice = input("파일 번호를 입력하세요 (종료: 0): ")
                if choice.isdigit():
                    choice = int(choice)
                    if choice == 0:
                        print('프로그램을 종료합니다.')
                        return None
                    elif 1 <= choice <= len(file_list):
                        selected_file = file_list[choice - 1]
                        logger.info(f"파일 '{selected_file}'을 선택했습니다.")
                        return selected_file
                print('유효하지 않은 번호입니다. 다시 시도하세요.')
            except (KeyboardInterrupt, EOFError):
                print('\n입력이 취소되었습니다.')
                return None
    
    def remove_extension(self, filename):
        """파일 이름에서 확장자를 제거합니다."""
        return os.path.splitext(filename)[0]
