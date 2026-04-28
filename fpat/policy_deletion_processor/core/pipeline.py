#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
정책 삭제 프로세스용 파이프라인 엔진 및 태스크 레지스트리
"""

import logging
from typing import List, Dict, Any, Type, Optional

logger = logging.getLogger(__name__)

class TaskRegistry:
    """작업 번호와 프로세서를 매핑하는 레지스트리"""
    
    @staticmethod
    def get_processor_info(task_id: int) -> Optional[Dict[str, Any]]:
        """
        작업 번호에 해당하는 프로세서 클래스와 기본 인자를 반환합니다.
        순환 참조 방지를 위해 메서드 내부에서 로컬 임포트를 수행합니다.
        """
        # 모듈과 클래스 이름이 다른 경우를 대비해 명시적으로 임포트
        import fpat.policy_deletion_processor.processors.request_parser as request_parser
        import fpat.policy_deletion_processor.processors.request_extractor as request_extractor
        import fpat.policy_deletion_processor.processors.mis_id_adder as mis_id_adder
        import fpat.policy_deletion_processor.processors.application_aggregator as application_aggregator
        import fpat.policy_deletion_processor.processors.request_info_adder as request_info_adder
        import fpat.policy_deletion_processor.processors.exception_handler as exception_handler
        import fpat.policy_deletion_processor.processors.duplicate_policy_classifier as duplicate_policy_classifier
        import fpat.policy_deletion_processor.processors.merge_hitcount as merge_hitcount
        import fpat.policy_deletion_processor.processors.policy_usage_processor as policy_usage_processor
        import fpat.policy_deletion_processor.processors.notification_classifier as notification_classifier
        import fpat.policy_deletion_processor.processors.auto_renewal_checker as auto_renewal_checker
        import fpat.policy_deletion_processor.processors.auto_collector as auto_collector
        import fpat.policy_deletion_processor.processors.redundancy_processor as redundancy_processor

        registry = {
            0: {"class": auto_collector.AutoCollector, "kwargs": {}},
            1: {"class": request_parser.RequestParser, "kwargs": {}},
            2: {"class": request_extractor.RequestExtractor, "kwargs": {}},
            3: {"class": mis_id_adder.MisIdAdder, "kwargs": {}},
            4: {"class": application_aggregator.ApplicationAggregator, "kwargs": {}},
            5: {"class": request_info_adder.RequestInfoAdder, "kwargs": {}},
            6: {"class": exception_handler.ExceptionHandler, "kwargs": {"vendor": "paloalto"}},
            7: {"class": exception_handler.ExceptionHandler, "kwargs": {"vendor": "secui"}},
            8: {"class": duplicate_policy_classifier.DuplicatePolicyClassifier, "kwargs": {"mode": "classify"}},
            9: {"class": duplicate_policy_classifier.DuplicatePolicyClassifier, "kwargs": {"mode": "update"}},
            10: {"class": merge_hitcount.MergeHitcount, "kwargs": {}},
            11: {"class": policy_usage_processor.PolicyUsageProcessor, "kwargs": {"mode": "add"}},
            12: {"class": policy_usage_processor.PolicyUsageProcessor, "kwargs": {"mode": "update"}},
            13: {"class": notification_classifier.NotificationClassifier, "kwargs": {}},
            14: {"class": auto_renewal_checker.AutoRenewalChecker, "kwargs": {}},
            15: {"class": redundancy_processor.RedundancyProcessor, "kwargs": {}}
        }
        return registry.get(task_id)

class Pipeline:
    """여러 프로세서를 순차적으로 실행하는 엔진"""
    
    def __init__(self, config, file_manager, excel_manager=None):
        self.config = config
        self.file_manager = file_manager
        self.excel_manager = excel_manager
        self.steps: List[Dict[str, Any]] = []

    def add_step(self, task_id: int, **custom_kwargs):
        """실행할 단계를 추가합니다."""
        info = TaskRegistry.get_processor_info(task_id)
        if info:
            processor_class = info["class"]
            kwargs = info["kwargs"].copy()
            kwargs.update(custom_kwargs)
            
            # excel_manager가 필요한 프로세서에 대해 주입
            from fpat.policy_deletion_processor.processors.notification_classifier import NotificationClassifier
            if processor_class == NotificationClassifier:
                kwargs["excel_manager"] = self.excel_manager
                
            self.steps.append({
                "id": task_id,
                "processor": processor_class(self.config),
                "kwargs": kwargs
            })
        else:
            logger.error(f"유효하지 않은 작업 번호: {task_id}")

    def run(self) -> bool:
        """등록된 모든 단계를 순차적으로 실행합니다."""
        for step in self.steps:
            task_id = step["id"]
            processor = step["processor"]
            kwargs = step["kwargs"]
            
            logger.info(f"파이프라인 단계 시작: Task {task_id} ({processor.__class__.__name__})")
            
            if not processor.run(self.file_manager, **kwargs):
                logger.error(f"파이프라인 단계 실패: Task {task_id}")
                return False
                
            logger.info(f"파이프라인 단계 완료: Task {task_id}")
            
        return True
