# src/agents/agent_data_ingestion.py

import paramiko
import winrm
import pandas as pd
import yaml
import keyring
import logging
import json
import re
import shlex
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

CONNECTION_TIMEOUT = 30
KNOWLEDGE_BASE_FILE = "knowledge_base.yaml"

class DataIngestionAgent:
    """
    Handles the entire data ingestion process, from reading the inventory
    to discovering hosts concurrently and persisting the data.
    """

    def __init__(self, inventory_path, db_manager, max_workers=10):
        self.inventory_path = inventory_path
        self.db_manager = db_manager
        self.max_workers = max_workers
        self.console = Console()
        self.knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self):
        """Loads the YAML knowledge base file."""
        try:
            with open(KNOWLEDGE_BASE_FILE, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.warning(f"Knowledge base file not found at '{KNOWLEDGE_BASE_FILE}'. Using defaults.")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"Error parsing knowledge base file: {e}")
            return {}

    def _validate_inventory(self, inventory_df):
        """Validates the inventory DataFrame."""
        required_columns = ['ip', 'os_type', 'user']
        if inventory_df.empty:
            self.console.print("[bold red]Error: Inventory file is empty. Aborting.[/bold red]")
            return False
        if not all(col in inventory_df.columns for col in required_columns):
            missing = set(required_columns) - set(inventory_df.columns)
            self.console.print(f"[bold red]Error: Inventory file is missing required columns: {missing}. Aborting.[/bold red]")
            return False
        return True

    def run_discovery(self):
        """Orchestrates the discovery and data persistence process."""
        try:
            inventory = pd.read_csv(self.inventory_path)
            if not self._validate_inventory(inventory):
                return
            self.console.print(f"Loaded and validated [bold]{len(inventory)}[/bold] hosts from '{self.inventory_path}'.")
        except FileNotFoundError:
            self.console.print(f"[bold red]Error: Inventory file not found at '{self.inventory_path}'.[/bold red]")
            return
        except pd.errors.EmptyDataError:
            self.console.print(f"[bold red]Error: Inventory file '{self.inventory_path}' is empty. Aborting.[/bold red]")
            return

        config_targets = self.knowledge_base.get('config_files', [])
        all_results = []
        progress_columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()]
        
        with Progress(*progress_columns, console=self.console) as progress:
            inventory_task = progress.add_task("[green]Discovering hosts...", total=len(inventory))
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_host = {executor.submit(self._discover_host_worker, row, config_targets): row for _, row in inventory.iterrows()}
                for future in as_completed(future_to_host):
                    res = future.result()
                    all_results.append(res)
                    progress.update(inventory_task, advance=1)
                    if res['status'] != 'Success':
                        self.console.print(f"\n[bold red]Discovery failed for {res['ip']}:[/bold red] {res.get('error', 'Unknown error')}")

        self._persist_results(all_results)

    def _discover_host_worker(self, host_info, config_targets):
        """Worker function for a single host."""
        ip = host_info['ip']
        os_type = host_info['os_type'].lower()
        user = host_info['user']
        result = {"ip": ip, "status": "Failed", "data": {}, "error": None}
        
        password = keyring.get_password("ai-migration-tool", user)
        if not password:
            result["error"] = f"Password for user '{user}' not found in keyring."
            return result
            
        try:
            if os_type == 'linux':
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(ip, username=user, password=password, timeout=CONNECTION_TIMEOUT)
                result["data"] = self._get_all_linux_data_resilient(ssh_client, user, config_targets)
                ssh_client.close()
                result["status"] = "Success"
            elif os_type == 'windows':
                win_session = winrm.Protocol(endpoint=f"http://{ip}:5985/wsman", transport='ntlm', username=user, password=password, server_cert_validation='ignore', read_timeout_sec=CONNECTION_TIMEOUT + 30)
                result["data"] = self._get_all_windows_data_resilient(win_session, user, config_targets)
                result["status"] = "Success"
            else:
                result["error"] = f"Unsupported OS type: {os_type}"
        except Exception as e:
            result["error"] = f"Connection failed: {e}"
        return result

    def _execute_linux_command(self, ssh_client, command):
        """Executes a command on the remote Linux host and returns the output."""
        try:
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=30)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8', errors='ignore').strip()
            if exit_code != 0:
                error_msg = stderr.read().decode('utf-8', errors='ignore').strip()
                logging.warning(f"Command '{command}' failed with exit code {exit_code}: {error_msg}")
                return None
            return output
        except Exception as e:
            logging.error(f"Exception executing command '{command}': {e}")
            return None

    def _execute_windows_command(self, win_session, command):
        """Executes a PowerShell command and returns the output."""
        try:
            result = win_session.run_ps(command)
            if result.status_code == 0:
                return result.std_out.decode('utf-8', errors='ignore').strip()
            else:
                error_msg = result.std_err.decode('utf-8', errors='ignore').strip()
                logging.warning(f"PowerShell command failed with status code {result.status_code}: {error_msg}")
                return None
        except Exception as e:
            logging.error(f"Exception executing PowerShell command: {e}")
            return None

    # --- Linux Discovery Methods ---
    def _discover_linux_os(self, ssh):
        try:
            data = {}
            output = self._execute_linux_command(ssh, "cat /etc/os-release 2>/dev/null")
            if output:
                for line in output.splitlines():
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key == "PRETTY_NAME": data['os_name'] = value.strip('"')
                        if key == "VERSION_ID": data['os_version'] = value.strip('"')
            hostname_out = self._execute_linux_command(ssh, "hostname")
            if hostname_out: data['hostname'] = hostname_out
            return data
        except Exception as e: logging.error(f"Failed to discover Linux OS: {e}"); return {}

    def _discover_linux_hardware(self, ssh):
        try:
            data = {}
            cpu_out = self._execute_linux_command(ssh, "lscpu | grep '^CPU(s):' | awk '{print $2}'")
            if cpu_out: data['cpu_cores'] = int(cpu_out)
            mem_out = self._execute_linux_command(ssh, "grep MemTotal /proc/meminfo | awk '{print $2}'")
            if mem_out: data['total_memory_gb'] = round(int(mem_out) / 1024**2, 2)
            return data
        except Exception as e: logging.error(f"Failed to discover Linux hardware: {e}"); return {}

    def _discover_linux_processes(self, ssh):
        """Discovers running processes and enhances them with their listening ports."""
        try:
            command = "ps -eo pid,user:20,stat,comm,args --no-headers"
            output = self._execute_linux_command(ssh, command)
            if not output: return []
            processes = []
            executable_paths = set()
            for line in output.strip().splitlines():
                try:
                    parts = line.strip().split(None, 4)
                    if len(parts) >= 5:
                        command_line = parts[4]
                        exe_path = shlex.split(command_line)[0] if command_line else None
                        if exe_path and exe_path.startswith('/'):
                            executable_paths.add(exe_path)
                        processes.append({'pid': int(parts[0]), 'user': parts[1], 'state': parts[2], 'process_name': parts[3], 'command_line': command_line, 'executable_path': exe_path})
                except (ValueError, IndexError, AttributeError): continue
            
            path_to_package = {}
            if executable_paths:
                pkg_manager_cmd = "if command -v rpm >/dev/null; then echo rpm; elif command -v dpkg >/dev/null; then echo dpkg; fi"
                pkg_manager = self._execute_linux_command(ssh, pkg_manager_cmd)
                
                if pkg_manager == 'rpm':
                    paths_str = " ".join(f"'{p}'" for p in executable_paths)
                    pkg_command = f"for f in {paths_str}; do rpm -qf --queryformat '%{{NAME}}\\t%{{FILE}}\\n' \"$f\"; done"
                    pkg_output = self._execute_linux_command(ssh, pkg_command)
                    if pkg_output:
                        for line in pkg_output.splitlines():
                            if '\t' in line:
                                name, path = line.split('\t', 1)
                                path_to_package[path] = name
                elif pkg_manager == 'dpkg':
                    paths_str = " ".join(f"'{p}'" for p in executable_paths)
                    pkg_command = f"for f in {paths_str}; do dpkg -S \"$f\" 2>/dev/null; done"
                    pkg_output = self._execute_linux_command(ssh, pkg_command)
                    if pkg_output:
                        for line in pkg_output.splitlines():
                            if ':' in line:
                                name, path = line.split(':', 1)
                                path_to_package[path.strip()] = name

            listen_command = "ss -tlnp"
            listen_output = self._execute_linux_command(ssh, listen_command)
            pid_to_ports = defaultdict(list)
            if listen_output:
                for line in listen_output.strip().splitlines()[1:]:
                    try:
                        port = int(line.split()[3].rsplit(':', 1)[-1])
                        pid_match = re.search(r'pid=(\d+)', line)
                        if pid_match: pid_to_ports[int(pid_match.group(1))].append(port)
                    except (ValueError, IndexError): continue
            
            for proc in processes:
                proc['listening_ports'] = pid_to_ports.get(proc['pid'], [])
                proc['owning_package'] = path_to_package.get(proc['executable_path'], None)
                
            return processes
        except Exception as e: logging.error(f"Failed to discover Linux processes: {e}"); return []

    def _discover_linux_network(self, ssh):
        try:
            command = "ss -tnp"
            output = self._execute_linux_command(ssh, command)
            if not output: return []
            connections = []
            line_regex = re.compile(r'(\S+)\s+\S+\s+\S+\s+\S+\s+([\d\.:\*]+)\s+.*users:\(\("([^"]+)",pid=(\d+),.*\)\)')
            for line in output.strip().splitlines()[1:]:
                match = line_regex.search(line)
                if match:
                    try:
                        state, peer_addr_port, process_name, pid = match.groups()
                        dest_ip, dest_port = peer_addr_port.rsplit(':', 1)
                        connections.append({'destination_ip': dest_ip, 'destination_port': int(dest_port), 'state': state, 'process_name': process_name, 'source_pid': int(pid)})
                    except (ValueError, IndexError) as e:
                        logging.warning(f"Could not parse network connection line: '{line}'. Error: {e}")
                        continue
            return connections
        except Exception as e: logging.error(f"Failed to discover Linux network connections: {e}"); return []

    def _discover_linux_software(self, ssh):
        try:
            command = "if command -v rpm >/dev/null; then rpm -qa --queryformat '%{NAME}\\t%{VERSION}\\t%{VENDOR}\\n'; elif command -v dpkg >/dev/null; then dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n'; fi"
            output = self._execute_linux_command(ssh, command)
            if output:
                return [{'name': p[0], 'version': p[1], 'vendor': p[2]} for p in (line.split('\t') for line in output.splitlines()) if len(p) == 3]
            return []
        except Exception as e: logging.error(f"Failed to discover Linux software: {e}"); return []

    def _discover_linux_storage(self, ssh):
        try:
            command = "df -PTk"
            output = self._execute_linux_command(ssh, command)
            mounts = []
            if output:
                line_regex = re.compile(r'^(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+\d+%\s+(.*)$')
                for line in output.strip().splitlines()[1:]:
                    match = line_regex.match(line)
                    if match:
                        try:
                            source, fstype, total_k, used_k, target = match.groups()
                            storage_type = "NAS" if fstype in ['nfs', 'nfs4', 'cifs'] else "DAS"
                            mounts.append({'source': source, 'mount_point': target, 'filesystem_type': fstype, 'storage_type': storage_type, 'total_gb': round(int(total_k) / 1024**2, 2), 'used_gb': round(int(used_k) / 1024**2, 2)})
                        except (ValueError, IndexError) as e:
                            logging.warning(f"Could not parse storage line: '{line}'. Error: {e}")
                            continue
            output = self._execute_linux_command(ssh, "multipath -ll 2>/dev/null")
            if output:
                for mount in mounts:
                    if '/dev/dm-' in mount['source']: mount['storage_type'] = "SAN"
            return mounts
        except Exception as e: logging.error(f"Failed to discover Linux storage: {e}"); return []

    def _discover_linux_scheduled_tasks(self, ssh):
        try:
            command = "cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^\\s*#' | grep -v '^\\s*$'"
            output = self._execute_linux_command(ssh, command)
            tasks = []
            if output:
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) < 6: continue
                    schedule = " ".join(parts[:5])
                    command_str = " ".join(parts[6:])
                    tasks.append({'name': f'CronJob-{len(tasks)+1}', 'command': command_str, 'schedule': schedule, 'enabled': True})
            return tasks
        except Exception as e: logging.error(f"Failed to discover Linux scheduled tasks: {e}"); return []

    def _discover_linux_open_files(self, ssh, pids):
        try:
            if not pids: return []
            pid_str = ",".join(map(str, pids))
            command = f"sudo lsof -p {pid_str} -n -P -F pn"
            output = self._execute_linux_command(ssh, command)
            if not output: return []
            
            open_files = []
            current_pid = None
            for line in output.splitlines():
                if not line: continue
                line_type = line[0]
                data = line[1:]
                if line_type == 'p':
                    try:
                        current_pid = int(data)
                    except ValueError:
                        current_pid = None
                elif line_type == 'n' and current_pid is not None:
                    if data.startswith('/') and 'deleted' not in data:
                         open_files.append({'pid': current_pid, 'file_path': data})
            return open_files
        except Exception as e: 
            logging.error(f"Failed to discover Linux open files: {e}")
            return []

    def _discover_and_parse_config_files(self, ssh_or_win, os_type, config_targets):
        if not config_targets: return []
        found_files = []
        for target in config_targets:
            try:
                file_name = target.get('name')
                search_paths = target.get('paths', ['/etc', '/opt', '/var/www'])
                if os_type == 'windows': search_paths = target.get('win_paths', ['C:\\Program Files', 'C:\\inetpub'])
                
                path_str = " ".join(search_paths) if os_type == 'linux' else ",".join([f"'{p}'" for p in search_paths])
                find_command = f"find {path_str} -name '{file_name}' -type f 2>/dev/null" if os_type == 'linux' else f"Get-ChildItem -Path {path_str} -Recurse -Filter '{file_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName"
                
                executor = self._execute_linux_command if os_type == 'linux' else self._execute_windows_command
                output = executor(ssh_or_win, find_command)
                if not output: continue

                for file_path in output.strip().splitlines():
                    file_path = file_path.strip()
                    content_command = f"cat '{file_path}'" if os_type == 'linux' else f"Get-Content -Path '{file_path}' | Out-String"
                    content = executor(ssh_or_win, content_command)
                    if content is None: continue

                    file_data = {'file_path': file_path, 'content': content, 'extracted_config_pairs': []}
                    if 'parsers' in target:
                        for parser in target['parsers']:
                            matches = re.findall(parser['regex'], content, re.MULTILINE)
                            if matches: file_data['extracted_config_pairs'].append({'key': parser['key'], 'value': matches[0]})
                    found_files.append(file_data)
            except Exception as e: logging.warning(f"Could not process config target {target.get('name')}: {e}")
        return found_files

    def _get_all_linux_data_resilient(self, ssh, user, config_targets):
        """Gathers all data from a Linux host by calling individual, resilient discovery methods."""
        all_data = {}
        peer = ssh.get_transport().getpeername()[0]
        logging.info(f"[{user}@{peer}] Discovering OS...")
        all_data.update(self._discover_linux_os(ssh))
        logging.info(f"[{user}@{peer}] Discovering hardware...")
        all_data.update(self._discover_linux_hardware(ssh))
        logging.info(f"[{user}@{peer}] Discovering processes, ports, and packages...")
        all_data['running_processes'] = self._discover_linux_processes(ssh)
        pids = [p['pid'] for p in all_data.get('running_processes', [])]
        logging.info(f"[{user}@{peer}] Discovering network...")
        all_data['network_connections'] = self._discover_linux_network(ssh)
        logging.info(f"[{user}@{peer}] Discovering software...")
        all_data['installed_software'] = self._discover_linux_software(ssh)
        logging.info(f"[{user}@{peer}] Discovering storage...")
        all_data['storage_mounts'] = self._discover_linux_storage(ssh)
        logging.info(f"[{user}@{peer}] Discovering scheduled tasks...")
        all_data['scheduled_tasks'] = self._discover_linux_scheduled_tasks(ssh)
        logging.info(f"[{user}@{peer}] Discovering open files for {len(pids)} processes...")
        all_data['open_files'] = self._discover_linux_open_files(ssh, pids)
        logging.info(f"[{user}@{peer}] Discovering config files...")
        all_data['config_files'] = self._discover_and_parse_config_files(ssh, 'linux', config_targets)
        return all_data

    # --- Windows Discovery Methods ---
    def _discover_windows_os(self, win):
        try:
            command = "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | ConvertTo-Json -Compress"
            output = self._execute_windows_command(win, command)
            if not output: return {}
            os_info = json.loads(output)
            hostname_out = self._execute_windows_command(win, "hostname")
            return {'os_name': os_info.get('Caption'), 'os_version': os_info.get('Version'), 'hostname': hostname_out}
        except Exception as e: logging.error(f"Failed to discover Windows OS: {e}"); return {}

    def _discover_windows_hardware(self, win):
        try:
            data = {}
            command = "(Get-CimInstance Win32_Processor).NumberOfCores"
            output = self._execute_windows_command(win, command)
            if output: data['cpu_cores'] = int(output)
            command = "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)"
            output = self._execute_windows_command(win, command)
            if output: data['total_memory_gb'] = float(output)
            return data
        except Exception as e: logging.error(f"Failed to discover Windows hardware: {e}"); return {}

    def _discover_windows_processes(self, win):
        """Discovers running processes on Windows and enhances them with their listening ports."""
        try:
            command = "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, @{N='User';E={$_.GetOwner().User}}, @{N='State';E={'Running'}}, CommandLine | ConvertTo-Json -Compress"
            output = self._execute_windows_command(win, command)
            if not output: return []
            processes = []
            win_procs = json.loads(output)
            if isinstance(win_procs, dict): win_procs = [win_procs]
            for p in win_procs:
                processes.append({'pid': p.get('ProcessId'), 'process_name': p.get('Name'), 'user': p.get('User'), 'state': p.get('State'), 'command_line': p.get('CommandLine')})
            
            listen_command = "Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | ConvertTo-Json -Compress"
            listen_output = self._execute_windows_command(win, listen_command)
            pid_to_ports = defaultdict(list)
            if listen_output:
                listen_info = json.loads(listen_output)
                if isinstance(listen_info, dict): listen_info = [listen_info]
                for item in listen_info:
                    pid = item.get('OwningProcess')
                    port = item.get('LocalPort')
                    if pid and port:
                        pid_to_ports[pid].append(port)
            
            for proc in processes:
                proc['listening_ports'] = pid_to_ports.get(proc['pid'], [])
            return processes
        except Exception as e: logging.error(f"Failed to discover Windows processes: {e}"); return []
        
    def _get_all_windows_data_resilient(self, win_session, user, config_targets):
        """Gathers all data from a Windows host by calling individual, resilient discovery methods."""
        all_data = {}
        peer = win_session.endpoint.split('/')[2].split(':')[0]
        logging.info(f"[{user}@{peer}] Discovering OS...")
        all_data.update(self._discover_windows_os(win_session))
        logging.info(f"[{user}@{peer}] Discovering hardware...")
        all_data.update(self._discover_windows_hardware(win_session))
        logging.info(f"[{user}@{peer}] Discovering processes and listening ports...")
        all_data['running_processes'] = self._discover_windows_processes(win_session)
        logging.info(f"[{user}@{peer}] Discovering config files...")
        all_data['config_files'] = self._discover_and_parse_config_files(win_session, 'windows', config_targets)
        # Note: Other Windows discovery methods (network, storage, etc.) would be added here.
        return all_data

    def _persist_results(self, all_results):
        """Persists all successfully collected data to the database."""
        self.console.rule("[bold blue]Persisting Data[/bold blue]")
        successful_hosts = [res for res in all_results if res['status'] == 'Success']
        if not successful_hosts:
            self.console.print("[yellow]No data to persist.[/yellow]")
            return

        servers_to_add = [(res['data'].get('hostname', res['ip']), res['ip'], res['data'].get('os_name'), res['data'].get('os_version'), res['data'].get('cpu_cores'), res['data'].get('total_memory_gb'), datetime.now().strftime("%Y-%m-%d %H:%M:%S")) for res in successful_hosts]
        self.db_manager.add_servers_bulk(servers_to_add)
        server_id_map = self.db_manager.get_server_ips_to_ids()

        for res in successful_hosts:
            server_id = server_id_map.get(res['ip'])
            if not server_id:
                logging.warning(f"Could not find server_id for IP {res['ip']} during persistence. Skipping.")
                continue
            
            try:
                self.db_manager.conn.execute('BEGIN')
                self.db_manager.clear_snapshot_data_for_server(server_id)
                data = res.get('data', {})
                
                if data.get('running_processes'): self.db_manager.add_applications_bulk([(server_id, p.get('process_name'), p.get('pid'), p.get('user'), p.get('state'), p.get('command_line'), json.dumps(p.get('listening_ports', [])), p.get('owning_package')) for p in data.get('running_processes', [])])
                if data.get('network_connections'): self.db_manager.add_network_connections_bulk([(server_id, c['destination_ip'], c['destination_port'], c['state'], c['process_name'], c['source_pid']) for c in data.get('network_connections', [])])
                if data.get('installed_software'): self.db_manager.add_installed_software_bulk([(server_id, s.get('name'), s.get('version'), s.get('vendor')) for s in data.get('installed_software', [])])
                if data.get('storage_mounts'): self.db_manager.add_storage_mounts_bulk([(server_id, m.get('source'), m.get('mount_point'), m.get('filesystem_type'), m.get('storage_type'), m.get('total_gb'), m.get('used_gb')) for m in data.get('storage_mounts', [])])
                if data.get('scheduled_tasks'): self.db_manager.add_scheduled_tasks_bulk([(server_id, t.get('name'), t.get('command'), t.get('schedule'), t.get('enabled')) for t in data.get('scheduled_tasks', [])])
                if data.get('open_files'): self.db_manager.add_process_open_files_bulk([(server_id, f.get('pid'), f.get('file_path')) for f in data.get('open_files', [])])
                
                if data.get('config_files'):
                    configs_to_add = [(server_id, f.get('file_path'), f.get('content')) for f in data.get('config_files', [])]
                    self.db_manager.add_config_files_bulk(configs_to_add)
                    pairs_to_add = [(server_id, f.get('file_path'), pair.get('key'), pair.get('value')) for f in data.get('config_files', []) for pair in f.get('extracted_config_pairs', [])]
                    if pairs_to_add: self.db_manager.add_extracted_config_pairs_bulk(pairs_to_add)

                self.db_manager.conn.commit()
                logging.info(f"Successfully persisted data for host {res['ip']}.")
            except Exception as e:
                self.db_manager.conn.rollback()
                logging.error(f"Failed to persist data for host {res['ip']}. Rolled back. Error: {e}")

        self.console.print("[green]Data persistence complete.[/green]")