#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
방화벽 데이터 자동 추출 및 사용이력 병합 프로세서
"""

import logging
import threading
import os
from datetime import datetime
from .base_processor import BaseProcessor
from .merge_hitcount import MergeHitcount
from ...firewall_module.collector_factory import FirewallCollectorFactory
from ...firewall_module.exporter import export_policy_to_excel

logger = logging.getLogger(__name__)

class AutoCollector(BaseProcessor):
    """방화벽 데이터를 추출하고 Pri/Sec 사용이력을 자동으로 병합하는 클래스"""
    
    def run(self, file_manager, **kwargs):
        """자동 추출 및 병합을 수행합니다."""
        vendor = kwargs.get('vendor')
        pri_info = kwargs.get('pri_info')
        sec_info = kwargs.get('sec_info')
        
        if not vendor or not pri_info:
            logger.error("방화벽 정보가 부족합니다.")
            return False

        try:
            results = {}
            threads = []
            today = datetime.now().strftime('%Y-%m-%d')
            
            # 출력 폴더 생성
            if not os.path.exists("outputs"):
                os.makedirs("outputs")

            # 1. Pri 장비 전체 데이터 추출 (Policy, Objects, Usage)
            def collect_pri():
                logger.info(f"Primary 장비 데이터 추출 시작: {pri_info['hostname']}")
                output = os.path.join("outputs", f"{today}_{pri_info['hostname']}_policy.xlsx")
                export_policy_to_excel(
                    vendor=vendor,
                    hostname=pri_info['hostname'],
                    username=pri_info['username'],
                    password=pri_info['password'],
                    export_type='all',
                    output_path=output
                )
                results['pri'] = output

            # 2. Sec 장비 사용이력 추출 (필요한 경우)
            def collect_sec():
                if not sec_info:
                    return
                logger.info(f"Secondary 장비 사용이력 추출 시작: {sec_info['hostname']}")
                output = os.path.join("outputs", f"{today}_{sec_info['hostname']}_usage.xlsx")
                export_policy_to_excel(
                    vendor=vendor,
                    hostname=sec_info['hostname'],
                    username=sec_info['username'],
                    password=sec_info['password'],
                    export_type='usage',
                    output_path=output
                )
                results['sec'] = output

            t1 = threading.Thread(target=collect_pri)
            threads.append(t1)
            if sec_info:
                t2 = threading.Thread(target=collect_sec)
                threads.append(t2)

            for t in threads: t.start()
            for t in threads: t.join()

            # 3. 사용이력 병합 (Task 10 로직 호출)
            if 'sec' in results:
                logger.info("Pri/Sec 사용이력 병합 시작...")
                # FileManager에 파일 강제 주입하여 MergeHitcount 실행
                file_manager.set_forced_files([results['pri'], results['sec']])
                merger = MergeHitcount(self.config)
                success = merger.run(file_manager)
                
                # [개선] 다음 단계(Task 15)에서 분석을 위해 pri_full 파일을 다시 사용하도록 큐에 삽입
                if success:
                    file_manager.set_forced_files([results['pri']])
                return success
            
            # HA가 아닌 경우 추출된 파일 경로를 큐에 삽입하여 다음 단계에서 바로 사용 가능하게 함
            file_manager.set_forced_files([results['pri']])
            return True

        except Exception as e:
            logger.exception(f"자동 추출 중 오류 발생: {e}")
            return False
