#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FPAT EXE 빌드 자동화 스크립트
"""

import os
import subprocess
import sys
import shutil

def build():
    print("🚀 FPAT 단일 EXE 빌드를 시작합니다...")
    
    # 1. PyInstaller 설치 확인
    try:
        import PyInstaller
    except ImportError:
        print("❌ PyInstaller가 설치되어 있지 않습니다. 설치를 진행합니다.")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

    # 2. 빌드 설정
    entry_point = os.path.join("fpat", "__main__.py")
    exe_name = "fpat"
    
    # 리소스 경로 설정 (Flask templates, static)
    checker_dir = os.path.join("fpat", "paloalto_parameter_checker")
    data_files = [
        (os.path.join(checker_dir, "templates"), os.path.join("fpat", "paloalto_parameter_checker", "templates")),
        (os.path.join(checker_dir, "static"), os.path.join("fpat", "paloalto_parameter_checker", "static")),
    ]
    
    # PyInstaller 명령어 구성
    cmd = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",      # 단일 파일 빌드
        "--console",      # 콘솔 창 활성화
        f"--name={exe_name}",
        # fpat 패키지 전체 수집
        "--collect-all=fpat",
        # 의존성 강제 수집 (pandas, openpyxl 등)
        "--collect-all=pandas",
        "--collect-all=openpyxl",
        "--collect-all=jinja2",
        "--collect-all=flask",
    ]
    
    # 리소스 추가 (--add-data "source:dest")
    separator = ";" if os.name == "nt" else ":"
    for src, dest in data_files:
        if os.path.exists(src):
            cmd.append(f"--add-data={src}{separator}{dest}")
    
    # 엔트리 포인트 추가
    cmd.append(entry_point)
    
    # 3. 빌드 실행
    try:
        print(f"🛠️ 빌드 명령어 실행 중: {' '.join(cmd)}")
        subprocess.check_call(cmd)
        print("\n✅ 빌드가 성공적으로 완료되었습니다!")
        print(f"📦 생성된 파일: {os.path.join('dist', exe_name)}")
        
        # 4. 설정 파일 복사 가이드
        if os.path.exists("fpat.yaml"):
            print(f"\n💡 팁: 실행 시 'fpat.yaml' 파일을 {exe_name} 파일과 같은 경로에 두세요.")
            
    except subprocess.CalledProcessError as e:
        print(f"\n❌ 빌드 중 오류가 발생했습니다: {e}")
        sys.exit(1)

if __name__ == "__main__":
    build()
