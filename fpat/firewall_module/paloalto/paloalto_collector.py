# firewall/paloalto/paloalto_collector.py
import pandas as pd
import re
import datetime
import time
import paramiko
import logging
from typing import Optional, Union
from ..firewall_interface import FirewallInterface
from .paloalto_module import PaloAltoAPI

from ..exceptions import (
    FirewallConnectionError, 
    FirewallAuthenticationError, 
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
        Args:
        config_type (str): 'running' 또는 'candidate' 중 하나. 기본은 'running'.
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
        API 타임아웃 버그 대응용이며, 대용량 정책의 경우 수 시간이 소요될 수 있습니다.
        """
        target_vsys_list = ['vsys1']
        if vsys:
            target_vsys_list = [str(v) for v in vsys]

        self.logger.info(f"SSH를 통한 히트카운트 수집 시작 (Target vsys: {target_vsys_list})")
        all_results = []

        ssh = None
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # 장시간 연결을 위한 Keep-alive 설정
            ssh.connect(
                self.hostname, 
                port=22, 
                username=self.username, 
                password=self._password, 
                timeout=30, 
                look_for_keys=False, 
                allow_agent=False
            )
            
            transport = ssh.get_transport()
            if transport:
                transport.set_keepalive(60)

            channel = ssh.invoke_shell()
            
            def send_and_wait(command: str, wait_timeout: int = 15):
                channel.send(command + "\n")
                output = ""
                start_time = time.time()
                while time.time() - start_time < wait_timeout:
                    if channel.recv_ready():
                        chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                        output += chunk
                        if output.strip().endswith(('>', '#')):
                            return output
                    time.sleep(0.5)
                return output

            # CLI 설정
            send_and_wait("", 10) # 초기 배너 대기
            send_and_wait("set cli scripting-mode on")
            send_and_wait("set cli pager off")

            for vsys_name in target_vsys_list:
                command = f"show rule-hit-count vsys vsys-name {vsys_name} rule-base security rules all"
                self.logger.info(f"명령어 전송 ({vsys_name}): {command}")
                self.logger.info("장비에서 리포트를 생성 중입니다. 대용량 정책의 경우 응답 시작까지 수 분에서 수 시간이 걸릴 수 있습니다.")
                channel.send(command + "\n")

                line_buffer = ""
                parsing_started = False
                rule_count = 0
                total_bytes = 0
                start_time = time.time()
                last_heartbeat = start_time
                data_started = False

                while True:
                    if channel.recv_ready():
                        if not data_started:
                            self.logger.info(f"[{vsys_name}] 데이터 수신 시작!")
                            data_started = True
                        
                        chunk_raw = channel.recv(16384)
                        total_bytes += len(chunk_raw)
                        chunk = chunk_raw.decode('utf-8', errors='ignore')
                        line_buffer += chunk
                        
                        while "\n" in line_buffer:
                            line, line_buffer = line_buffer.split("\n", 1)
                            line = line.strip()
                            
                            if not line: continue
                            if '----------' in line:
                                parsing_started = True
                                continue
                            if not parsing_started: continue
                            if line.startswith('intrazone-default'):
                                parsing_started = False
                                break

                            match = re.match(r'^([a-zA-Z0-9/._-]+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}|-)', line)
                            if match:
                                rule_name = match.group(1)
                                timestamp_str = match.group(3).strip()
                                last_hit_date = None
                                if timestamp_str != '-':
                                    try:
                                        norm_ts = re.sub(r'\s+', ' ', timestamp_str)
                                        dt_obj = datetime.datetime.strptime(norm_ts, '%a %b %d %H:%M:%S %Y')
                                        last_hit_date = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                                    except: pass
                                
                                all_results.append({"Vsys": vsys_name, "Rule Name": rule_name, "Last Hit Date": last_hit_date})
                                rule_count += 1

                        # 프롬프트 확인 시 종료
                        if line_buffer.strip().endswith(('>', '#')):
                            self.logger.info(f"[{vsys_name}] 수집 완료: 총 {rule_count}개 규칙 (수신 데이터: {total_bytes/1024:.1f} KB)")
                            break
                    else:
                        # 데이터를 기다리는 동안 심박수 로그 출력 (30초마다)
                        now = time.time()
                        if now - last_heartbeat > 30:
                            wait_elapsed = now - start_time
                            if not data_started:
                                self.logger.info(f"[{vsys_name}] 응답 대기 중... ({int(wait_elapsed)}초 경과)")
                            else:
                                self.logger.info(f"[{vsys_name}] 데이터 수신 중... (현재까지 {total_bytes/1024:.1f} KB)")
                            last_heartbeat = now
                    
                    if time.time() - start_time > 14400: # 4시간 전체 타임아웃
                        self.logger.error(f"[{vsys_name}] 최대 처리 시간 초과")
                        break
                    
                    time.sleep(0.1)

        except Exception as e:
            self.logger.error(f"SSH 수집 실패: {e}", exc_info=True)
            raise FirewallAPIError(f"SSH 기반 히트카운트 수집 중 오류: {e}")
        finally:
            if ssh:
                ssh.close()
                self.logger.info("SSH 연결 종료")

        return pd.DataFrame(all_results)
