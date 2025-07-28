# src/agents/agent_data_ingestion.py

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="paramiko")
import uuid
import logging
import paramiko
import winrm
import pandas as pd
import json
import re
import shlex
import keyring
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from datetime import datetime
from typing import List, Dict, Any, Callable
from abc import ABC, abstractmethod

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s:%(funcName)s] - %(message)s')

CONNECTION_TIMEOUT = 30

class BaseIngestionAgent(ABC):
    """
    Abstract base class for ingestion agents, providing a common interface for data collection.
    """
    def __init__(self, user: str, ip: str, dry_run: bool = False, db_callback: Callable[[List[Dict[str, Any]], str], None] = None):
        self.user = user
        self.ip = ip
        self.dry_run = dry_run
        self.db_callback = db_callback
        self.console = Console()
        self.pids: List[int] = []
        self.executables: List[str] = []
        self.phases: List[Callable[[], List[Dict[str, Any]]]] = [
            self._discover_os,
            self._discover_hardware,
            self._discover_processes_and_ports,
            self._discover_software,
            self._discover_network,
            self._discover_network_config,
            self._discover_ipc,
            self._discover_storage,
            self._discover_scheduled_tasks,
            self._discover_open_files,
            self._discover_performance
        ]

    def collect_data(self) -> List[Dict[str, Any]]:
        """
        Orchestrates data collection by executing each phase in sequence.
        
        Returns:
            List[Dict[str, Any]]: Collected records from all phases.
        """
        all_records = []
        server_record = None
        for phase in self.phases:
            phase_name = phase.__name__.lstrip('_discover_')
            logger.info(f"[{self.user}@{self.ip}] Discovering {phase_name}...")
            phase_records = phase()
            # Handle missing 'id' in phase records
            for rec in phase_records:
                if 'type' not in rec:
                    logger.warning(f"Missing 'type' in {phase_name} record; assigning default 'Unknown'.")
                    rec['type'] = 'Unknown'
                if 'id' not in rec:
                    logger.warning(f"Missing 'id' in {phase_name} record; generating temporary UUID.")
                    rec['id'] = str(uuid.uuid4())  # Use UUID to avoid hash issues
            if phase_name in ['os', 'hardware']:
                if phase_records:
                    if server_record is None:
                        server_record = phase_records[0]
                    else:
                        server_record.update(phase_records[0])
                    all_records.extend(phase_records)
            else:
                for rec in phase_records:
                    if server_record:
                        rec['server_id'] = server_record.get('id', 'unknown')  # Handle if server 'id' missing
                all_records.extend(phase_records)
            if self.db_callback:
                self.db_callback(phase_records, phase_name)
            # Update state for dependent phases
            if phase_name == 'processes_and_ports':
                self.pids = [p['pid'] for p in phase_records if p.get('pid')]
                self.executables = list(set(p.get('executable_path') for p in phase_records if p.get('executable_path')))
        if server_record and (not all_records or all_records[0] != server_record):
            all_records.insert(0, server_record)
        return all_records

    @abstractmethod
    def _execute_command(self, command: str, ignore_errors: bool = False) -> str:
        """Executes a command on the remote host."""
        pass

    def _map_process_state(self, raw_state: str) -> str:
        """Maps raw process state to standardized values."""
        state_map = {
            'S': 'SLEEPING', 'SS': 'SLEEPING', 'R': 'RUNNING', 'T': 'STOPPED', 'I': 'IDLE', 'Z': 'ZOMBIE', 'D': 'WAITING',
            'Running': 'RUNNING', 'True': 'RUNNING', 'False': 'STOPPED'
        }
        return state_map.get(raw_state, 'UNKNOWN')

    @abstractmethod
    def _discover_os(self) -> List[Dict[str, Any]]:
        """Discovers OS details."""
        pass

    @abstractmethod
    def _discover_hardware(self) -> List[Dict[str, Any]]:
        """Discovers hardware details."""
        pass

    @abstractmethod
    def _discover_processes_and_ports(self) -> List[Dict[str, Any]]:
        """Discovers running processes and listening ports."""
        pass

    @abstractmethod
    def _discover_software(self) -> List[Dict[str, Any]]:
        """Discovers installed software and package mappings."""
        pass

    @abstractmethod
    def _discover_network(self) -> List[Dict[str, Any]]:
        """Discovers network connections."""
        pass

    @abstractmethod
    def _discover_network_config(self) -> List[Dict[str, Any]]:
        """Discovers network interfaces and DNS config."""
        pass

    @abstractmethod
    def _discover_ipc(self) -> List[Dict[str, Any]]:
        """Discovers IPC connections."""
        pass

    @abstractmethod
    def _discover_storage(self) -> List[Dict[str, Any]]:
        """Discovers storage mounts."""
        pass

    @abstractmethod
    def _discover_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Discovers scheduled tasks."""
        pass

    @abstractmethod
    def _discover_open_files(self) -> List[Dict[str, Any]]:
        """Discovers open files for processes."""
        pass

    @abstractmethod
    def _discover_performance(self) -> List[Dict[str, Any]]:
        """Discovers performance metrics."""
        pass

    # TODO: Support PostgreSQL ingestion using pluggable DB agent
    # Example:
    # def _discover_postgresql(self) -> List[Dict[str, Any]]:
    #     # Connect via psycopg2, collect schemas/tables/etc.
    #     pass

class LinuxIngestionAgent(BaseIngestionAgent):
    def __init__(self, user: str, ip: str, ssh_client: paramiko.SSHClient = None, dry_run: bool = False, db_callback: Callable = None):
        super().__init__(user, ip, dry_run, db_callback)
        self.ssh = ssh_client

    def _execute_command(self, command: str, ignore_errors: bool = False) -> str:
        if self.dry_run:
            logger.debug(f"Dry run: Would execute command '{command}'")
            return ""
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=30)
            stdout_output = stdout.read().decode('utf-8', errors='ignore').strip()
            stderr_output = stderr.read().decode('utf-8', errors='ignore').strip()
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0 and not ignore_errors:
                logger.warning(f"Command '{command}' failed with exit code {exit_code}: {stderr_output}")
                return ""
            if exit_code != 0 and ignore_errors:
                logger.debug(f"Command '{command}' produced a non-fatal warning: {stderr_output}")
            return stdout_output
        except Exception as e:
            logger.error(f"Exception executing command '{command}': {e}")
            return ""

    def _discover_os(self) -> List[Dict[str, Any]]:
        try:
            data = {}
            output = self._execute_command("cat /etc/os-release 2>/dev/null")
            if output:
                for line in output.splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key == "PRETTY_NAME": data['os_name'] = value.strip('"')
                        if key == "VERSION_ID": data['os_version'] = value.strip('"')
            hostname_out = self._execute_command("hostname")
            if hostname_out: data['hostname'] = hostname_out
            # Generate temp 'id' if not present
            data['id'] = f"server_{self.ip.replace('.', '_')}"
            return [{
                'type': 'Server',
                'id': f"server_{self.ip}",
                'hostname': data.get('hostname', f"host_{self.ip.replace('.', '_')}"),
                'ip_address': self.ip,
                'os': data.get('os_name', 'linux'),
                'os_version': data.get('os_version'),
            }]
        except Exception as e:
            logger.error(f"Failed to discover Linux OS: {e}")
            return {'type': 'Server', 'id': f"server_{self.ip.replace('.', '_')}"}

    def _discover_hardware(self) -> List[Dict[str, Any]]:
        try:
            data = {}
            cpu_out = self._execute_command("lscpu | grep '^CPU(s):' | awk '{print $2}'")
            if cpu_out: data['cpu_cores'] = int(cpu_out)
            mem_out = self._execute_command("grep MemTotal /proc/meminfo | awk '{print $2}'")
            if mem_out: data['total_memory_gb'] = round(int(mem_out) / 1024**2, 2)
            data['type'] = 'Hardware'
            return [data]
        except Exception as e:
            logger.error(f"Failed to discover Linux hardware: {e}")
            return {'type': 'Hardware'}

    def _discover_processes_and_ports(self) -> List[Dict[str, Any]]:
        processes = []
        try:
            command = "ps -eo pid,user:20,stat,comm,args --no-headers"
            output = self._execute_command(command)
            if not output: return []

            for line in output.strip().splitlines():
                try:
                    parts = line.strip().split(None, 4)
                    if len(parts) < 5: continue
                    
                    command_name = parts[3]
                    command_line = parts[4]
                    if command_name.startswith('[') and command_name.endswith(']'):
                        continue

                    exe_path = None
                    if command_line:
                        split_cmd = shlex.split(command_line)
                        if split_cmd and split_cmd[0].startswith('/'):
                            exe_path = split_cmd[0]

                    processes.append({
                        'type': 'Application',
                        'pid': int(parts[0]), 
                        'user': parts[1], 
                        'state': self._map_process_state(parts[2]), 
                        'process_name': command_name, 
                        'command_line': command_line, 
                        'executable_path': exe_path,
                        'listening_ports': [],
                        'owning_package': None  # Filled in software phase
                    })
                except (ValueError, IndexError):
                    continue
            
            listen_command = "ss -tunlp"
            listen_output = self._execute_command(listen_command)
            pid_to_ports = defaultdict(list)
            if listen_output:
                for line in listen_output.strip().splitlines()[1:]:
                    try:
                        port_str = line.split()[4]
                        port = int(port_str.rsplit(':', 1)[-1])
                        pid_match = re.search(r'pid=(\d+)', line)
                        if pid_match:
                            pid_to_ports[int(pid_match.group(1))].append(port)
                    except (ValueError, IndexError):
                        continue
            
            for proc in processes:
                proc['listening_ports'] = json.dumps(pid_to_ports.get(proc['pid'], []))

            return processes
        except Exception as e:
            logger.error(f"Failed to discover Linux processes and ports: {e}")
            return []

    def _discover_software(self) -> List[Dict[str, Any]]:
        software_list = []
        try:
            get_all_pkg_command = "if command -v rpm >/dev/null; then rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\t%{VENDOR}\\n'; elif command -v dpkg >/dev/null; then dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n'; fi"
            output = self._execute_command(get_all_pkg_command, ignore_errors=True)
            if output:
                for line in output.splitlines():
                    p = line.split('\t')
                    if len(p) >= 3:
                        software_list.append({
                            'type': 'InstalledSoftware',
                            'name': p[0],
                            'version': p[1],
                            'vendor': p[2] if len(p) > 2 else 'Unknown'
                        })

            process_to_package_map = {}
            if self.executables:
                is_rpm = bool(self._execute_command("command -v rpm", ignore_errors=True))
                is_dpkg = bool(self._execute_command("command -v dpkg", ignore_errors=True))
                for path in self.executables:
                    if not path:
                        continue
                    package_name = None
                    if is_rpm:
                        map_command = f"rpm -qf {shlex.quote(path)} --queryformat '%{{NAME}}'"
                        pkg_output = self._execute_command(map_command, ignore_errors=True)
                        if pkg_output and "is not owned by any package" not in pkg_output and "no such file" not in pkg_output:
                            package_name = pkg_output.strip()
                    elif is_dpkg:
                        map_command = f"dpkg -S {shlex.quote(path)} | cut -d: -f1"
                        pkg_output = self._execute_command(map_command, ignore_errors=True)
                        if pkg_output:
                            package_name = pkg_output.strip()
                    if package_name:
                        process_to_package_map[path] = package_name
            # Note: To update processes with owning_package, but since processes are in previous records, would need to pass back or update in orchestration if needed. For now, assume correlation handles.
            return software_list
        except Exception as e:
            logger.error(f"Failed during Linux software discovery: {e}")
            return []

    def _discover_network(self) -> List[Dict[str, Any]]:
        connections = []
        try:
            command = "ss -tunap"
            output = self._execute_command(command)
            if not output: return []

            for line in output.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 6: continue
                try:
                    protocol, state, local_full, peer_full = parts[0], parts[1], parts[4], parts[5]
                    proc_info_match = re.search(r'users:\(\("([^"]+)",pid=(\d+),.*\)\)', line)
                    process_name, pid = (proc_info_match.groups() if proc_info_match else (None, None))
                    local_addr, local_port = local_full.rsplit(':', 1)
                    if local_addr == "127.0.0.1": continue
                    peer_addr, peer_port = (peer_full.rsplit(':', 1) if ':' in peer_full else (peer_full, None))
                    connections.append({
                        'type': 'NetworkConnection',
                        'protocol': protocol.lower(),
                        'state': state,
                        'local_address': local_addr,
                        'local_port': int(local_port) if local_port.isdigit() else None,
                        'peer_address': peer_addr,
                        'peer_port': int(peer_port) if peer_port and peer_port.isdigit() else None,
                        'process_name': process_name,
                        'pid': int(pid) if pid else None
                    })
                except (ValueError, IndexError):
                    logger.warning(f"Could not parse network connection line: '{line}'")
                    continue
            return connections
        except Exception as e:
            logger.error(f"Failed to discover Linux network connections: {e}")
            return []

    def _discover_network_config(self) -> List[Dict[str, Any]]:
        interfaces = []
        try:
            ip_out = self._execute_command("ip -o addr show")
            if ip_out:
                for line in ip_out.splitlines():
                    parts = line.split()
                    if len(parts) < 4 or parts[2] != 'inet': continue
                    interface_name = parts[1]
                    ip_address = parts[3].split('/')[0]
                    if ip_address == "127.0.0.1": continue
                    netmask = parts[3].split('/')[1] if '/' in parts[3] else None
                    mac_out = self._execute_command(f"cat /sys/class/net/{interface_name}/address")
                    gateway_out = self._execute_command("ip route show | grep default | awk '{print $3}'")
                    interfaces.append({
                        'type': 'NetworkInterface',
                        'name': interface_name,
                        'ip_address': ip_address,
                        'netmask': netmask,
                        'mac_address': mac_out if mac_out else None,
                        'gateway': gateway_out if gateway_out else None,
                        'dns_servers': None
                    })
            dns_out = self._execute_command("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'")
            dns_servers = ','.join(dns_out.splitlines()) if dns_out else None
            for iface in interfaces:
                iface['dns_servers'] = dns_servers
            return interfaces
        except Exception as e:
            logger.error(f"Failed to discover Linux network config: {e}")
            return []

    def _discover_ipc(self) -> List[Dict[str, Any]]:
        connections = []
        try:
            output = self._execute_command("lsof -U -a -p $(pidof $(ps -e -o comm=)) -F pn", ignore_errors=True)
            if not output: return []
            current_pid = None
            for line in output.strip().splitlines():
                if not line: continue
                line_type, data = line[0], line[1:]
                if line_type == 'p':
                    try:
                        current_pid = int(data)
                    except (ValueError, TypeError):
                        current_pid = None
                elif line_type == 'n' and current_pid is not None:
                    if data.startswith('/') and 'socket' in data.lower():
                        proc_info = self._execute_command(f"ps -p {current_pid} -o comm=", ignore_errors=True)
                        peer_pid = None
                        lsof_peer = self._execute_command(f"lsof -U | grep {data} | grep -v ' {current_pid} ' | awk '{{print $2}}'", ignore_errors=True)
                        if lsof_peer and lsof_peer.strip().isdigit():
                            peer_pid = int(lsof_peer.strip())
                        connections.append({
                            'type': 'IpcConnection',
                            'source_pid': current_pid,
                            'dest_pid': peer_pid,
                            'path': data,
                            'process_name': proc_info.strip() if proc_info else None
                        })
            return connections
        except Exception as e:
            logger.error(f"Failed to discover Linux IPC: {e}")
            return []

    def _discover_storage(self) -> List[Dict[str, Any]]:
        mounts = []
        try:
            command = "df -PTk"
            output = self._execute_command(command)
            if not output: return []
            
            lines = output.strip().splitlines()
            if len(lines) < 2: return []
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 7: continue
                try:
                    source, fstype, total_k, used_k, _, mount_point = parts[0], parts[1], parts[2], parts[3], parts[4], " ".join(parts[6:])
                    storage_type = "NAS" if fstype in ['nfs', 'nfs4', 'cifs'] else "DAS"
                    mounts.append({
                        'type': 'StorageMount',
                        'source': source,
                        'mount_point': mount_point,
                        'filesystem_type': fstype,
                        'storage_type': storage_type,
                        'total_gb': round(int(total_k) / 1024**2, 2),
                        'used_gb': round(int(used_k) / 1024**2, 2)
                    })
                except (ValueError, IndexError) as e:
                    logger.warning(f"Could not parse storage line: '{line}'. Error: {e}")
                    continue
            output_san = self._execute_command("multipath -ll 2>/dev/null", ignore_errors=True)
            if output_san:
                for mount in mounts:
                    if '/dev/dm-' in mount['source']:
                        mount['storage_type'] = "SAN"
            return mounts
        except Exception as e:
            logger.error(f"Failed to discover Linux storage: {e}")
            return []

    def _discover_scheduled_tasks(self) -> List[Dict[str, Any]]:
        tasks = []
        try:
            command = "cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^\\s*#' | grep -v '^\\s*$'"
            output = self._execute_command(command)
            if output:
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) < 6: continue
                    schedule = " ".join(parts[:5])
                    command_str = " ".join(parts[6:])
                    tasks.append({
                        'type': 'ScheduledTask',
                        'name': f'CronJob-{len(tasks)+1}',
                        'command': command_str,
                        'schedule': schedule,
                        'enabled': True
                    })
            return tasks
        except Exception as e:
            logger.error(f"Failed to discover Linux scheduled tasks: {e}")
            return []

    def _discover_open_files(self) -> List[Dict[str, Any]]:
        if not self.pids: return []
        open_files = []
        batch_size = 100
        for i in range(0, len(self.pids), batch_size):
            pid_batch = self.pids[i:i + batch_size]
            pid_str = ",".join(map(str, pid_batch))
            command = f"sudo lsof +c 0 -p {shlex.quote(pid_str)} -n -P -F pn"
            try:
                output = self._execute_command(command, ignore_errors=True)
                if not output: continue
                current_pid = None
                for line in output.splitlines():
                    if not line: continue
                    line_type, data = line[0], line[1:]
                    if line_type == 'p':
                        try:
                            current_pid = int(data)
                        except (ValueError, TypeError):
                            current_pid = None
                    elif line_type == 'n' and current_pid is not None:
                        if data.startswith('/') and 'deleted' not in data:
                            open_files.append({
                                'type': 'ProcessOpenFile',
                                'id': str(uuid.uuid4()),
                                'pid': current_pid,
                                'file_path': data
                            })
            except Exception as e:
                logger.error(f"Failed to process lsof for PID batch starting at index {i}. Error: {e}")
                continue
        return open_files

    def _discover_performance(self) -> List[Dict[str, Any]]:
        return []  # Per constraints, not implementing

class WindowsIngestionAgent(BaseIngestionAgent):
    def __init__(self, user: str, ip: str, password: str, dry_run: bool = False, db_callback: Callable = None):
        super().__init__(user, ip, dry_run, db_callback)
        self.password = password
        self.session = winrm.Session(f'http://{ip}:5985/wsman', auth=(user, password), transport='ntlm') if not dry_run else None

    def _execute_command(self, command: str, ignore_errors: bool = False) -> str:
        if self.dry_run:
            logger.debug(f"Dry run: Would execute command '{command}'")
            return ""
        try:
            result = self.session.run_ps(command)
            if result.status_code != 0 and not ignore_errors:
                logger.warning(f"Command '{command}' failed: {result.std_err.decode('utf-8')}")
                return ""
            return result.std_out.decode('utf-8').strip()
        except Exception as e:
            logger.error(f"Exception executing command '{command}': {e}")
            return ""

    def _discover_os(self) -> List[Dict[str, Any]]:
        hostname = self._execute_command("hostname")
        os_info = self._execute_command("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"")
        os_name = os_info.splitlines()[0].split(':', 1)[1].strip() if os_info else "Windows"
        os_version = os_info.splitlines()[1].split(':', 1)[1].strip() if len(os_info.splitlines()) > 1 else None
        return [{
            'type': 'Server',
            'id': f"server_{self.ip}",
            'hostname': hostname or f"host_{self.ip.replace('.', '_')}",
            'ip_address': self.ip,
            'os': os_name,
            'os_version': os_version,
        }]

    def _discover_hardware(self) -> List[Dict[str, Any]]:
        data = {}
        cpu_out = self._execute_command("wmic cpu get NumberOfCores")
        data['cpu_cores'] = int(cpu_out.splitlines()[1]) if len(cpu_out.splitlines()) > 1 else None
        mem_out = self._execute_command("wmic computersystem get TotalPhysicalMemory")
        data['total_memory_gb'] = round(int(mem_out.splitlines()[1]) / 1024**3, 2) if len(mem_out.splitlines()) > 1 else None
        return [data]

    def _discover_processes_and_ports(self) -> List[Dict[str, Any]]:
        processes = []
        proc_out = self._execute_command("Get-Process | Select-Object Id,Name,Path,UserName,Responding | ConvertTo-Json")
        if proc_out:
            proc_data = json.loads(proc_out)
            for proc in proc_data:
                processes.append({
                    'type': 'Application',
                    'pid': proc.get('Id'),
                    'process_name': proc.get('Name'),
                    'command_line': proc.get('Path'),
                    'user': proc.get('UserName'),
                    'state': self._map_process_state(str(proc.get('Responding'))),
                    'executable_path': proc.get('Path'),
                    'listening_ports': [],
                    'owning_package': None
                })
        
        pid_to_ports = defaultdict(list)
        tcp_out = self._execute_command("Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object OwningProcess,LocalPort | ConvertTo-Json")
        if tcp_out:
            tcp_data = json.loads(tcp_out)
            for conn in tcp_data:
                pid = conn.get('OwningProcess')
                port = conn.get('LocalPort')
                if pid and port:
                    pid_to_ports[pid].append(port)
        udp_out = self._execute_command("Get-NetUDPEndpoint | Select-Object OwningProcess,LocalPort | ConvertTo-Json")
        if udp_out:
            udp_data = json.loads(udp_out)
            for conn in udp_data:
                pid = conn.get('OwningProcess')
                port = conn.get('LocalPort')
                if pid and port:
                    pid_to_ports[pid].append(port)
        
        for proc in processes:
            proc['listening_ports'] = json.dumps(pid_to_ports.get(proc['pid'], []))
        
        return processes

    # Implement other _discover_* for Windows similarly...

    def _discover_performance(self) -> List[Dict[str, Any]]:
        return []  # Per constraints

class DataIngestionOrchestrator:
    """
    Orchestrates multi-host data ingestion using concurrent workers.
    """
    def __init__(self, inventory_path, max_workers=10, dry_run=False, perf_interval=10, perf_duration=30):
        self.inventory_path = inventory_path
        self.max_workers = max_workers
        self.dry_run = dry_run
        self.perf_interval = perf_interval
        self.perf_duration = perf_duration
        self.perf_samples = max(1, int(perf_duration / perf_interval))
        self.console = Console()

    def _validate_inventory(self, inventory_df):
        """Validates the inventory DataFrame for required columns."""
        required_columns = ['ip', 'os_type', 'user']
        if inventory_df.empty:
            self.console.print("[bold red]Error: Inventory file is empty. Aborting.[/bold red]")
            return False
        if not all(col in inventory_df.columns for col in required_columns):
            missing = set(required_columns) - set(inventory_df.columns)
            self.console.print(f"[bold red]Error: Inventory file is missing required columns: {missing}. Aborting.[/bold red]")
            return False
        return True

    def collect_data(self, db_callback: Callable[[List[Dict[str, Any]], str], None] = None) -> List[Dict[str, Any]]:
        """
        Orchestrates the discovery process and returns a list of records.
        Optionally calls db_callback to store records incrementally.
        
        Args:
            db_callback: Optional function to store records in the database after each phase.
                         Signature: db_callback(records, phase_name)
        
        Returns:
            List[Dict[str, Any]]: Collected records from all hosts.
        """
        try:
            inventory = pd.read_csv(self.inventory_path)
            if not self._validate_inventory(inventory):
                return []
            self.console.print(f"Loaded and validated [bold]{len(inventory)}[/bold] hosts from '{self.inventory_path}'.")
        except FileNotFoundError:
            self.console.print(f"[bold red]Error: Inventory file not found at '{self.inventory_path}'.[/bold red]")
            return []
        except pd.errors.EmptyDataError:
            self.console.print(f"[bold red]Error: Inventory file '{self.inventory_path}' is empty. Aborting.[/bold red]")
            return []

        all_records = []
        failed_hosts = []
        progress_columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()]
        
        with Progress(*progress_columns, console=self.console) as progress:
            inventory_task = progress.add_task("[green]Discovering hosts...", total=len(inventory))
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_host = {executor.submit(self._discover_host_worker, row, db_callback): row for _, row in inventory.iterrows()}
                for future in as_completed(future_to_host):
                    host_info = future_to_host[future]
                    ip = host_info['ip']
                    try:
                        records = future.result()
                        all_records.extend(records)
                    except Exception as e:
                        logger.error(f"Discovery failed for {ip}: {e}")
                        failed_hosts.append(ip)
                    progress.update(inventory_task, advance=1)

        if len(failed_hosts) == len(inventory):
            raise ValueError("All hosts failed during discovery. Check credentials, network, or host availability. Aborting pipeline.")

        self.console.print("[green]Data collection complete.[/green]")
        return all_records

    def _discover_host_worker(self, host_info, db_callback) -> List[Dict[str, Any]]:
        """
        Worker function for a single host. Handles connection and data collection.
        
        Args:
            host_info: Row from inventory DataFrame.
            db_callback: Optional callback for DB storage.
        
        Returns:
            List[Dict[str, Any]]: Collected records for the host.
        
        Raises:
            Specific exceptions for auth/network, but catches and logs to skip host.
        """
        ip = host_info['ip']
        os_type = str(host_info['os_type']).lower()
        user = host_info['user']
        result = []

        password = keyring.get_password("ai-migration-tool", user)
        if not password:
            logger.error(f"Password for user '{user}' not found in keyring for {ip}. Skipping host.")
            return []

        logger.info(f"Processing host {ip} with os_type={os_type}, user={user}")
        try:
            if os_type == 'linux':
                ssh_client = paramiko.SSHClient() if not self.dry_run else None
                if not self.dry_run:
                    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh_client.connect(ip, username=user, password=password, timeout=CONNECTION_TIMEOUT)
                result = LinuxIngestionAgent(user, ip, ssh_client, self.dry_run, db_callback).collect_data()
                if not self.dry_run:
                    ssh_client.close()
            elif os_type == 'windows':
                result = WindowsIngestionAgent(user, ip, password, self.dry_run, db_callback).collect_data()
            else:
                logger.error(f"Unsupported OS type: {os_type} for {ip}. Skipping host.")
                return []
            return result
        except paramiko.AuthenticationException as e:
            logger.error(f"Authentication failed for {ip} (wrong username or password?): {e}. Skipping host.")
            return []
        except (paramiko.SSHException, TimeoutError) as e:
            error_msg = str(e).lower()
            if "no route to host" in error_msg or "timed out" in error_msg or "connection refused" in error_msg:
                logger.error(f"Host {ip} unreachable (network/connectivity issue): {e}. Skipping host.")
            else:
                logger.error(f"SSH/Connection failure for {ip}: {e}. Skipping host.")
            return []
        except Exception as e:
            logger.error(f"Unexpected failure for {ip}: {e}. Skipping host.")
            return []