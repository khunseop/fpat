#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
정책 삭제 프로세스 통합 파이프라인
"""

import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class Pipeline:
    """여러 프로세서를 순서대로 실행하는 파이프라인 클래스"""
    
    def __init__(self, config, file_manager, excel_manager):
        self.config = config
        self.file_manager = file_manager
        self.excel_manager = excel_manager
        self.steps = []

    def add_step(self, task_id: int, **kwargs):
        """실행할 태스크를 파이프라인에 추가"""
        task_info = self._get_task_info(task_id)
        if task_info:
            # 전달받은 kwargs를 기존 설정에 병합
            merged_kwargs = task_info.get("kwargs", {}).copy()
            merged_kwargs.update(kwargs)
            self.steps.append((task_info["class"], merged_kwargs))
        else:
            logger.error(f"알 수 없는 태스크 ID: {task_id}")

    def _get_task_info(self, task_id: int) -> Optional[Dict[str, Any]]:
        """
        태스크 ID에 해당하는 클래스와 기본 인자 반환.
        순환 참조 방지를 위해 메서드 내부에서 로컬 임포트를 수행합니다.
        """
        try:
            from fpat.policy_deletion_processor.processors.request_parser import RequestParser
            from fpat.policy_deletion_processor.processors.request_extractor import RequestExtractor
            from fpat.policy_deletion_processor.processors.mis_id_adder import MisIdAdder
            from fpat.policy_deletion_processor.processors.application_aggregator import ApplicationAggregator
            from fpat.policy_deletion_processor.processors.request_info_adder import RequestInfoAdder
            from fpat.policy_deletion_processor.processors.exception_handler import ExceptionHandler
            from fpat.policy_deletion_processor.processors.bottom_latest_policy_validator import BottomLatestPolicyValidator
            from fpat.policy_deletion_processor.processors.duplicate_policy_classifier import DuplicatePolicyClassifier
            from fpat.policy_deletion_processor.processors.duplicate_expired_cleaner import DuplicateExpiredCleaner
            from fpat.policy_deletion_processor.processors.duplicate_exception_applier import DuplicateExceptionApplier
            from fpat.policy_deletion_processor.processors.merge_hitcount import MergeHitcount
            from fpat.policy_deletion_processor.processors.policy_usage_processor import PolicyUsageProcessor
            from fpat.policy_deletion_processor.processors.auto_renewal_checker import AutoRenewalChecker
            from fpat.policy_deletion_processor.processors.notification_classifier import NotificationClassifier
            from fpat.policy_deletion_processor.processors.auto_collector import AutoCollector
            from fpat.policy_deletion_processor.processors.redundancy_processor import RedundancyProcessor

            registry = {
                0: {"class": AutoCollector, "kwargs": {}},
                1: {"class": RequestParser, "kwargs": {}},
                2: {"class": RequestExtractor, "kwargs": {}},
                3: {"class": MisIdAdder, "kwargs": {}},
                4: {"class": ApplicationAggregator, "kwargs": {}},
                5: {"class": RequestInfoAdder, "kwargs": {}},
                6: {"class": ExceptionHandler, "kwargs": {"vendor": "paloalto"}},
                7: {"class": ExceptionHandler, "kwargs": {"vendor": "secui"}},
                8: {"class": BottomLatestPolicyValidator, "kwargs": {}},
                9: {"class": DuplicatePolicyClassifier, "kwargs": {"mode": "classify"}},
                10: {"class": DuplicatePolicyClassifier, "kwargs": {"mode": "update"}},
                11: {"class": DuplicateExpiredCleaner, "kwargs": {}},
                12: {"class": MergeHitcount, "kwargs": {}},
                13: {"class": PolicyUsageProcessor, "kwargs": {"mode": "add"}},
                14: {"class": PolicyUsageProcessor, "kwargs": {"mode": "update"}},
                15: {"class": AutoRenewalChecker, "kwargs": {}},
                16: {"class": NotificationClassifier, "kwargs": {}},
                17: {"class": RedundancyProcessor, "kwargs": {}},
                18: {"class": DuplicateExceptionApplier, "kwargs": {}}
            }

            return registry.get(int(task_id))
        except ImportError as e:
            logger.error(f"프로세서 로드 실패: {e}")
            raise

    def run(self) -> bool:
        """파이프라인 실행"""
        if not self.steps:
            logger.warning("실행할 태스크가 없습니다.")
            return True

        for processor_class, kwargs in self.steps:
            # BaseProcessor는 config만 인자로 받음
            processor = processor_class(self.config)
            logger.info(f"태스크 실행: {processor_class.__name__}")
            
            # excel_manager를 kwargs에 포함시켜 전달
            run_kwargs = kwargs.copy()
            run_kwargs['excel_manager'] = self.excel_manager
            
            if not processor.run(self.file_manager, **run_kwargs):
                logger.error(f"태스크 실패: {processor_class.__name__}")
                return False
        
        return True
