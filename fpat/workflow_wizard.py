#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FPAT 통합 워크플로우 위저드 (TUI)
"""

import sys
import os
import getpass
import logging
from pathlib import Path

# 패키지 경로 추가
current_file = Path(__file__).resolve()
sys.path.insert(0, str(current_file.parent.parent))

from fpat.policy_deletion_processor.core.config_manager import ConfigManager
from fpat.policy_deletion_processor.core.pipeline import Pipeline
from fpat.policy_deletion_processor.utils.file_manager import FileManager
from fpat.policy_deletion_processor.utils.excel_manager import ExcelManager

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("=" * 60)
    print("      🔥 FPAT Firewall Policy Cleanup Workflow Wizard 🔥")
    print("=" * 60)

def get_input(prompt, default=None):
    if default:
        res = input(f"{prompt} [{default}]: ").strip()
        return res if res else default
    return input(f"{prompt}: ").strip()

def workflow_wizard():
    config = ConfigManager()
    file_manager = FileManager(config)
    excel_manager = ExcelManager(config)
    
    clear_screen()
    print_banner()
    
    print("\n[단계 1] 방화벽 데이터 수집 설정")
    print("-" * 30)
    vendor = get_input("방화벽 벤더 (paloalto/ngf/mf2)", "paloalto")
    
    pri_ip = get_input("Primary 장비 IP/Hostname")
    user = get_input("접속 계정", "admin")
    pw = getpass.getpass("접속 비밀번호: ")
    
    pri_info = {"hostname": pri_ip, "username": user, "password": pw}
    
    has_ha = get_input("HA 구성(Secondary 장비)이 있습니까? (y/n)", "y").lower() == 'y'
    sec_info = None
    if has_ha:
        sec_ip = get_input("Secondary 장비 IP/Hostname")
        sec_info = {"hostname": sec_ip, "username": user, "password": pw}
    
    print("\n[단계 2] 워크플로우 실행 모드 선택")
    print("-" * 30)
    print("1. 전체 자동 공정 (추출 -> 병합 -> 중복분석 -> 기본 예외처리)")
    print("2. 데이터 추출 및 병합만 수행 (Task 0)")
    print("3. 기존 파일을 이용한 분석 파이프라인 실행 (Task 1-15)")
    
    mode = get_input("선택", "1")
    
    pipeline = Pipeline(config, file_manager, excel_manager)
    
    if mode == "1":
        # 전체 자동 공정 시나리오: 추출 -> 병합 -> 중복분석 -> 파싱 -> 예외처리 -> 미사용반영
        print("\n[!] 전체 자동 공정 시나리오를 구성합니다.")
        
        # 1. 데이터 수집 및 HA 병합 (Task 0)
        pipeline.add_step(0, vendor=vendor, pri_info=pri_info, sec_info=sec_info)
        
        # 2. 중복 정책 분석 (Task 15)
        pipeline.add_step(15, vendor=vendor)
        
        # 3. 신청번호 파싱 (Task 1)
        pipeline.add_step(1)
        
        # 4. 벤더별 기본 예외처리 (Task 6 or 7)
        # 인프라/차단/신규정책 등을 마킹하여 분석 효율을 높입니다.
        if vendor == 'paloalto':
            pipeline.add_step(6)
        else:
            pipeline.add_step(7)
            
        # 5. 미사용 정보 반영 (Task 11)
        # 병합된 사용이력을 메인 정책 파일에 업데이트합니다.
        pipeline.add_step(11)
        
        print(f"-> 파이프라인 구성 완료: Task 0, 15, 1, {'6' if vendor=='paloalto' else '7'}, 11")
        
    elif mode == "2":
        pipeline.add_step(0, vendor=vendor, pri_info=pri_info, sec_info=sec_info)
        
    elif mode == "3":
        print("\n실행할 태스크 번호를 공백으로 구분하여 입력하세요.")
        print("예: 1 2 5 8 11 (파싱, 추출, 매칭, 중복분류, 미사용반영)")
        task_input = get_input("태스크 번호")
        if task_input:
            tasks = task_input.split()
            for t in tasks:
                pipeline.add_step(int(t))
        else:
            print("태스크 번호가 입력되지 않았습니다.")
            return
            
    print("\n" + "=" * 60)
    print("🚀 워크플로우 실행을 시작합니다...")
    print("=" * 60 + "\n")
    
    if pipeline.run():
        print("\n" + "✅ 모든 작업이 성공적으로 완료되었습니다!")
    else:
        print("\n" + "❌ 작업 수행 중 오류가 발생했습니다. 로그를 확인하세요.")

if __name__ == "__main__":
    try:
        workflow_wizard()
    except KeyboardInterrupt:
        print("\n\n[!] 사용자에 의해 종료되었습니다.")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"예기치 못한 오류 발생: {e}")
        sys.exit(1)
