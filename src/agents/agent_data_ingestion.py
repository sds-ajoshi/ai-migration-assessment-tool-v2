import paramiko
import re
from datetime import datetime, timedelta
import winrm
import json
import time
from typing import List, Dict
from collections import defaultdict

def execute_ssh_command(ssh_client, command, timeout=15):
    """Executes a command on a Linux host via the given SSH client."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
    except Exception as e:
        return "", str(e)

def execute_ps_command(winrm_session, command):
    """Executes a PowerShell command on a Windows host via WinRM."""
    try:
        ps_script = f"powershell -Command \"{command} | ConvertTo-Json -Compress\""
        result = winrm_session.run_ps(ps_script)
        if result.status_code == 0:
            json_output = result.std_out.decode('utf-8').strip()
            return json.loads(json_output) if json_output else None, None
        else:
            return None, result.std_err.decode('utf-8').strip()
    except Exception as e:
        return None, str(e)

def _parse_proc_stat(stdout: str) -> Dict:
    """Helper to parse the first line of /proc/stat."""
    if not stdout: return {}
    parts = stdout.splitlines()[0].split()
    cpu_times = [int(p) for p in parts[1:]]
    return {'user': cpu_times[0], 'nice': cpu_times[1], 'system': cpu_times[2], 'idle': cpu_times[3], 'iowait': cpu_times[4], 'total': sum(cpu_times)}

def _parse_diskstats(stdout: str) -> Dict:
    """Helper to parse /proc/diskstats."""
    stats = {}
    for line in stdout.splitlines():
        parts = line.split()
        device_name = parts[2]
        if not device_name.isalpha() and not (device_name[-1].isdigit() or device_name.startswith('nvme')):
            continue
        stats[device_name] = {
            'reads_completed': int(parts[3]), 'writes_completed': int(parts[7]),
            'sectors_read': int(parts[5]), 'sectors_written': int(parts[9])
        }
    return stats

def discover_linux_hw(ssh_client, username):
    """Discovers hardware details from a Linux host."""
    hw_details = {}
    print("  [*] Discovering Linux Hardware...")
    stdout, _ = execute_ssh_command(ssh_client, "lscpu")
    for line in stdout.splitlines():
        match = re.search(r'^CPU\(s\):\s*(\d+)', line)
        if match: hw_details['cpu_cores'] = int(match.group(1))
    stdout, _ = execute_ssh_command(ssh_client, "grep MemTotal /proc/meminfo")
    match = re.search(r'MemTotal:\s*(\d+)\s*kB', stdout)
    if match: hw_details['total_memory_gb'] = round(int(match.group(1)) / (1024 * 1024), 2)
    return hw_details

def discover_linux_sw(ssh_client):
    """
    Discovers software and process details from a Linux host, with robust
    process name parsing.
    """
    sw_details = {}
    print("  [*] Discovering Linux Software...")
    stdout, _ = execute_ssh_command(ssh_client, "hostname")
    sw_details['hostname'] = stdout.strip()
    stdout, _ = execute_ssh_command(ssh_client, "cat /etc/os-release")
    for line in stdout.splitlines():
        if line.startswith("PRETTY_NAME="): sw_details['os_name'] = line.split('=')[1].strip().strip('"')
        elif line.startswith("VERSION_ID="): sw_details['os_version'] = line.split('=')[1].strip().strip('"')
    
    stdout, _ = execute_ssh_command(ssh_client, "ps -eo pid,user,stat,args --no-headers")
    processes = []
    for line in stdout.strip().splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            pid, user, state, command_line = parts
            
            # --- ROBUST PARSING LOGIC ---
            process_name = ""
            cmd_str = command_line.strip()
            # Handle kernel threads enclosed in brackets
            if cmd_str.startswith('[') and cmd_str.endswith(']'):
                process_name = cmd_str[1:-1]
            else:
                # The process name is the first part of the command line before any spaces
                executable_path = cmd_str.split()[0]
                # The name is the part after the last slash
                process_name = executable_path.split('/')[-1]
            
            processes.append({
                'pid': int(pid),
                'user': user,
                'state': state,
                'process_name': process_name,
                'command_line': cmd_str
            })
    sw_details['running_processes'] = processes
    return sw_details

def discover_linux_network(ssh_client):
    """Discovers active TCP network connections from a Linux host."""
    print("  [*] Discovering Linux network connections...")
    connections = []
    stdout, _ = execute_ssh_command(ssh_client, "ss -tnp")
    line_regex = re.compile(r'^(ESTAB)\s+\d+\s+\d+\s+[\d\.:]+:\d+\s+([\d\.:]+):(\d+)\s+users:\(\("(.+?)",pid=(\d+),.*\)\)$')
    for line in stdout.splitlines()[1:]:
        match = line_regex.search(line)
        if match:
            state, dest_ip_raw, dest_port, process_name, pid = match.groups()
            dest_ip = dest_ip_raw.split(':')[-1]
            if dest_ip == "127.0.0.1" or dest_ip == "::1": continue
            connections.append({"destination_ip": dest_ip, "destination_port": int(dest_port), "state": state, "process_name": process_name, "process_pid": int(pid)})
    return connections

def discover_installed_software_linux(ssh_client):
    """Discovers installed software on a Linux/Unix host using a multi-step fallback process."""
    print("  [*] Discovering installed software (Linux/Unix)...")
    software_list = []
    stdout, _ = execute_ssh_command(ssh_client, "command -v dpkg-query")
    if stdout:
        print("    [-] Found DPKG package manager.")
        cmd = "dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n'"
        stdout, _ = execute_ssh_command(ssh_client, cmd)
        for line in stdout.strip().splitlines():
            parts = line.split('\t')
            if len(parts) == 3: software_list.append({"name": parts[0], "version": parts[1], "vendor": parts[2]})
        return software_list
    stdout, _ = execute_ssh_command(ssh_client, "command -v rpm")
    if stdout:
        print("    [-] Found RPM package manager.")
        cmd = "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\n'"
        stdout, _ = execute_ssh_command(ssh_client, cmd)
        for line in stdout.strip().splitlines():
            parts = line.split('\t')
            if len(parts) == 3: software_list.append({"name": parts[0], "version": parts[1], "vendor": parts[2]})
        return software_list
    return software_list

def discover_config_files(ssh_client, config_targets: List[Dict]):
    """Finds, downloads, and parses configuration files based on targets."""
    print("  [*] Discovering application configuration files...")
    discovered_files = []
    if not config_targets: return discovered_files
    for target in config_targets:
        target_name = target.get("name")
        search_paths = " ".join(target.get("paths", ["/etc"]))
        find_cmd = f"find {search_paths} -name {target_name} -type f 2>/dev/null"
        found_paths_str, _ = execute_ssh_command(ssh_client, find_cmd)
        for file_path in found_paths_str.strip().splitlines():
            print(f"    [-] Found potential config file: {file_path}")
            content, cat_err = execute_ssh_command(ssh_client, f"cat {file_path}")
            if "Permission denied" in cat_err:
                print(f"    [!] Permission denied for {file_path}. Trying with sudo...")
                content, sudo_err = execute_ssh_command(ssh_client, f"sudo cat {file_path}")
                if sudo_err: content = f"Error: Could not read file. Sudo failed: {sudo_err.strip()}"
            discovered_files.append({"file_path": file_path, "content": content})
    return discovered_files

def discover_storage_mounts_linux(ssh_client):
    """
    Discovers all storage mounts on a Linux host, identifying DAS, NAS, and SAN.
    Refactored to be more robust and compatible with older systems.
    """
    print("  [*] Discovering storage mounts (Linux)...")
    mounts = []
    san_devices = set()
    stdout, _ = execute_ssh_command(ssh_client, "command -v multipath")
    if stdout:
        print("    [-] Found multipath tools, checking for SAN LUNs...")
        mp_stdout, _ = execute_ssh_command(ssh_client, "multipath -ll")
        for line in mp_stdout.splitlines():
            match = re.search(r'\((\w+)\)\s+dm-\d+', line)
            if match: san_devices.add(f"/dev/mapper/{match.group(1)}")

    # --- REFINED LOGIC ---
    # 1. Try modern `df --output` command first
    df_cmd = "df --output=source,fstype,size,used,target"
    df_stdout, df_stderr = execute_ssh_command(ssh_client, df_cmd)

    # 2. If modern command fails, fall back to legacy command
    if "invalid option" in df_stderr or "unrecognized option" in df_stderr:
        print("    [!] 'df --output' not supported. Falling back to 'df -PT'.")
        df_cmd_fallback = "df -PT"
        df_stdout, df_stderr = execute_ssh_command(ssh_client, df_cmd_fallback)

        if df_stderr:
            print(f"    [-] Error running fallback df command: {df_stderr}")
            return mounts

        # Parse legacy 'df -PT' output
        for line in df_stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 7: continue
            source, fs_type, total_kb, used_kb, _, _, mount_point = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], " ".join(parts[6:])
            storage_type = "DAS"
            if fs_type.startswith("nfs") or fs_type == "cifs": storage_type = "NAS"
            elif source in san_devices: storage_type = "SAN"
            try:
                mounts.append({"source": source, "mount_point": mount_point, "filesystem_type": fs_type, "storage_type": storage_type, "total_gb": round(int(total_kb) / 1024, 2), "used_gb": round(int(used_kb) / 1024, 2)}) # Note: df -T reports in 1K-blocks
            except ValueError: continue
    
    elif df_stderr:
        print(f"    [-] Error running df command: {df_stderr}")
        return mounts

    else:
        # Parse modern 'df --output' output
        for line in df_stdout.strip().splitlines()[1:]:
            parts = line.split(maxsplit=4)
            if len(parts) < 5: continue
            source, fs_type, total_kb, used_kb, mount_point = parts
            storage_type = "DAS"
            if fs_type.startswith("nfs") or fs_type == "cifs": storage_type = "NAS"
            elif source in san_devices: storage_type = "SAN"
            try:
                mounts.append({"source": source, "mount_point": mount_point, "filesystem_type": fs_type, "storage_type": storage_type, "total_gb": round(int(total_kb) / (1024*1024), 2), "used_gb": round(int(used_kb) / (1024*1024), 2)})
            except ValueError: continue
            
    return mounts

def discover_process_open_files(ssh_client, pids: List[int]):
    """For a given list of Process IDs, find all open files using lsof."""
    if not pids: return {}
    print("  [*] Discovering open files for running processes...")
    pid_str = ",".join(map(str, pids))
    command = f"lsof -p {pid_str} -n -P | awk '{{print $2, $9}}'"
    stdout, _ = execute_ssh_command(ssh_client, command)
    open_files_map = defaultdict(list)
    for line in stdout.strip().splitlines():
        try:
            pid, file_path = line.split(maxsplit=1)
            if file_path.startswith('/'):
                open_files_map[int(pid)].append(file_path)
        except ValueError: continue
    return open_files_map

def _collect_perf_from_proc(ssh_client, duration_minutes, interval_seconds):
    """Fallback performance collection method using the /proc filesystem."""
    print("  [*] 'sysstat' not found. Using fallback performance collection from /proc.")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    stdout_stat, _ = execute_ssh_command(ssh_client, "cat /proc/stat")
    stdout_disk, _ = execute_ssh_command(ssh_client, "cat /proc/diskstats")
    if not stdout_stat or not stdout_disk: return []
    last_cpu_stats = _parse_proc_stat(stdout_stat)
    last_disk_stats = _parse_diskstats(stdout_disk)
    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        # print(f"  [*] Collecting /proc data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        # CPU
        stdout, _ = execute_ssh_command(ssh_client, "cat /proc/stat")
        if stdout:
            current_cpu_stats = _parse_proc_stat(stdout)
            delta_total = current_cpu_stats['total'] - last_cpu_stats['total']
            delta_idle = current_cpu_stats['idle'] - last_cpu_stats['idle']
            if delta_total > 0:
                cpu_util = 100.0 * (1.0 - (delta_idle / delta_total))
                all_metrics.append({'metric_name': 'cpu_percent_utilization', 'value': round(cpu_util, 2), 'timestamp': collection_timestamp})
            last_cpu_stats = current_cpu_stats
        # Memory
        stdout, _ = execute_ssh_command(ssh_client, "cat /proc/meminfo")
        if stdout:
            mem_total = mem_available = 0
            for line in stdout.splitlines():
                if line.startswith("MemTotal:"): mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"): mem_available = int(line.split()[1])
            if mem_total > 0:
                mem_used_percent = 100.0 * ((mem_total - mem_available) / mem_total)
                all_metrics.append({'metric_name': 'memory_percent_used', 'value': round(mem_used_percent, 2), 'timestamp': collection_timestamp})
        # Disk
        stdout, _ = execute_ssh_command(ssh_client, "cat /proc/diskstats")
        if stdout:
            current_disk_stats = _parse_diskstats(stdout)
            for device, curr_stats in current_disk_stats.items():
                last_stats = last_disk_stats.get(device)
                if last_stats:
                    reads_iops = (curr_stats['reads_completed'] - last_stats['reads_completed']) / interval_seconds
                    writes_iops = (curr_stats['writes_completed'] - last_stats['writes_completed']) / interval_seconds
                    read_mbs = ((curr_stats['sectors_read'] - last_stats['sectors_read']) * 512) / (1024 * 1024 * interval_seconds)
                    write_mbs = ((curr_stats['sectors_written'] - last_stats['sectors_written']) * 512) / (1024 * 1024 * interval_seconds)
                    all_metrics.extend([
                        {'metric_name': f'disk_iops_read_{device}', 'value': round(reads_iops, 2), 'timestamp': collection_timestamp},
                        {'metric_name': f'disk_iops_write_{device}', 'value': round(writes_iops, 2), 'timestamp': collection_timestamp},
                        {'metric_name': f'disk_throughput_read_mbs_{device}', 'value': round(read_mbs, 2), 'timestamp': collection_timestamp},
                        {'metric_name': f'disk_throughput_write_mbs_{device}', 'value': round(write_mbs, 2), 'timestamp': collection_timestamp}
                    ])
            last_disk_stats = current_disk_stats
        time.sleep(interval_seconds)
    return all_metrics

def _collect_perf_with_sysstat(ssh_client, duration_minutes, interval_seconds):
    """Primary performance collection method using sar/iostat."""
    print("  [*] 'sysstat' package found. Using 'sar' and 'iostat' for collection.")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        # print(f"  [*] Collecting sysstat data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        # CPU
        stdout, _ = execute_ssh_command(ssh_client, "sar -u 1 1")
        lines = stdout.strip().splitlines()
        if len(lines) > 2 and 'Average:' not in lines[-1] and lines[-1].split()[1] == 'all':
            cpu_data = lines[-1].split()
            all_metrics.extend([
                {'metric_name': 'cpu_percent_user', 'value': float(cpu_data[2]), 'timestamp': collection_timestamp},
                {'metric_name': 'cpu_percent_system', 'value': float(cpu_data[4]), 'timestamp': collection_timestamp},
                {'metric_name': 'cpu_percent_iowait', 'value': float(cpu_data[5]), 'timestamp': collection_timestamp},
                {'metric_name': 'cpu_percent_idle', 'value': float(cpu_data[7]), 'timestamp': collection_timestamp}
            ])
        # Memory
        stdout, _ = execute_ssh_command(ssh_client, "sar -r 1 1")
        lines = stdout.strip().splitlines()
        if len(lines) > 2 and 'Average:' not in lines[-1]:
            all_metrics.append({'metric_name': 'memory_percent_used', 'value': float(lines[-1].split()[3]), 'timestamp': collection_timestamp})
        # Disk
        stdout, _ = execute_ssh_command(ssh_client, "iostat -dx 1 2")
        devices_data = stdout.strip().split('\n\n')
        for block in devices_data:
            if block.startswith('Device'):
                 for line in block.strip().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 7:
                        device_name = parts[0]
                        all_metrics.extend([
                            {'metric_name': f'disk_iops_read_{device_name}', 'value': float(parts[1]), 'timestamp': collection_timestamp},
                            {'metric_name': f'disk_iops_write_{device_name}', 'value': float(parts[2]), 'timestamp': collection_timestamp}
                        ])
        # Network
        stdout, _ = execute_ssh_command(ssh_client, "sar -n DEV 1 1")
        lines = stdout.strip().splitlines()
        if len(lines) > 2:
            for line in lines[2:]:
                if 'Average:' in line or 'IFACE' in line: continue
                net_data = line.split()
                if len(net_data) >= 6:
                    iface = net_data[1]
                    if iface == 'lo': continue
                    all_metrics.extend([
                        {'metric_name': f'network_throughput_in_mbps_{iface}', 'value': round((float(net_data[4]) * 8) / 1024, 4), 'timestamp': collection_timestamp},
                        {'metric_name': f'network_throughput_out_mbps_{iface}', 'value': round((float(net_data[5]) * 8) / 1024, 4), 'timestamp': collection_timestamp}
                    ])
        time.sleep(interval_seconds)
    return all_metrics

def collect_linux_perf(ssh_client, duration_minutes: int, interval_seconds: int = 60):
    """Dispatcher function for Linux performance collection."""
    if duration_minutes == 0: return []
    print(f"[*] Starting {duration_minutes}-minute performance baseline for Linux host...")
    stdout, _ = execute_ssh_command(ssh_client, "command -v sar")
    if stdout:
        return _collect_perf_with_sysstat(ssh_client, duration_minutes, interval_seconds)
    else:
        return _collect_perf_from_proc(ssh_client, duration_minutes, interval_seconds)

def discover_scheduled_tasks_linux(ssh_client):
    """
    Discovers system-wide cron jobs from /etc/crontab and /etc/cron.d/.
    """
    print("  [*] Discovering scheduled tasks (Linux Cron)...")
    tasks = []
    # Combine system crontab and cron.d files into one command
    command = "cat /etc/crontab /etc/cron.d/* 2>/dev/null"
    stdout, _ = execute_ssh_command(ssh_client, command)
    
    # Regex to find valid cron lines, ignoring comments and env settings
    cron_line_regex = re.compile(r'^\s*([^#\s]+)\s+([^#\s]+)\s+([^#\s]+)\s+([^#\s]+)\s+([^#\s]+)\s+([^#\s]+)\s+(.*)')
    
    for line in stdout.strip().splitlines():
        match = cron_line_regex.search(line)
        if match:
            minute, hour, day_of_month, month, day_of_week, user, cmd = match.groups()
            schedule = f"{minute} {hour} {day_of_month} {month} {day_of_week}"
            tasks.append({
                "name": f"Cron: {user} - {cmd[:30]}...",
                "command": cmd,
                "schedule": schedule,
                "enabled": True
            })
    return tasks

def get_all_linux_data(ssh_client, user, perf_duration, perf_interval, config_targets):
    """Wrapper to call all Linux discovery functions and bundle the data."""
    hw_data = discover_linux_hw(ssh_client, user)
    sw_data = discover_linux_sw(ssh_client)
    net_data = discover_linux_network(ssh_client)
    installed_sw = discover_installed_software_linux(ssh_client)
    storage_mounts = discover_storage_mounts_linux(ssh_client)
    config_files = discover_config_files(ssh_client, config_targets)
    scheduled_tasks = discover_scheduled_tasks_linux(ssh_client)
    
    running_pids = [p['pid'] for p in sw_data.get('running_processes', [])]
    open_files_map = discover_process_open_files(ssh_client, running_pids)
    for proc in sw_data.get('running_processes', []):
        proc['open_files'] = open_files_map.get(proc['pid'], [])
        
    perf_data = collect_linux_perf(ssh_client, perf_duration, perf_interval)
    
    return {
        **hw_data, **sw_data, "network_connections": net_data,
        "installed_software": installed_sw, "storage_mounts": storage_mounts,
        "config_files": config_files, "scheduled_tasks": scheduled_tasks
    }, perf_data

# --- WINDOWS DISCOVERY FUNCTIONS ---

def discover_windows_hw(winrm_session):
    """Discovers hardware details from a Windows host."""
    hw_details = {}
    print("  [*] Discovering Windows Hardware...")
    cpu_info, _ = execute_ps_command(winrm_session, "Get-CimInstance -ClassName Win32_Processor | Select-Object NumberOfCores")
    if cpu_info:
        if isinstance(cpu_info, list): hw_details['cpu_cores'] = sum(c.get('NumberOfCores', 0) for c in cpu_info)
        else: hw_details['cpu_cores'] = cpu_info.get('NumberOfCores', 0)
    mem_info, _ = execute_ps_command(winrm_session, "Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object TotalPhysicalMemory")
    if mem_info:
        try: hw_details['total_memory_gb'] = round(int(mem_info.get('TotalPhysicalMemory', 0)) / (1024**3), 2)
        except (ValueError, TypeError): pass
    return hw_details

def discover_windows_sw(winrm_session):
    """
    Discovers software and process details from a Windows host, now including
    the full command line for each process.
    """
    sw_details = {}
    print("  [*] Discovering Windows Software...")
    hostname_info, _ = execute_ps_command(winrm_session, "$env:COMPUTERNAME")
    if hostname_info: sw_details['hostname'] = hostname_info
    os_info, _ = execute_ps_command(winrm_session, "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version")
    if os_info:
        sw_details['os_name'] = os_info.get('Caption')
        sw_details['os_version'] = os_info.get('Version')
    
    # --- Use Win32_Process to get CommandLine ---
    proc_info, _ = execute_ps_command(winrm_session, "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine")
    if proc_info:
        processes = []
        if not isinstance(proc_info, list): proc_info = [proc_info]
        for proc in proc_info:
            processes.append({
                'pid': proc.get('ProcessId'),
                'process_name': proc.get('Name'),
                'command_line': proc.get('CommandLine'),
                'user': None, # Getting user is a separate, more complex query
                'state': None # State is not directly available here
            })
        sw_details['running_processes'] = processes
    return sw_details

def discover_windows_network(winrm_session):
    """Discovers active TCP network connections from a Windows host."""
    print("  [*] Discovering Windows network connections...")
    connections = []
    command = "Get-NetTCPConnection -State Established | ForEach-Object { $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; $_ | Select-Object -Property RemoteAddress, RemotePort, State, @{Name='ProcessName';Expression={$proc.ProcessName}}, @{Name='OwningProcess';Expression={$_.OwningProcess}}}"
    conn_data, _ = execute_ps_command(winrm_session, command)
    if not conn_data: return connections
    if not isinstance(conn_data, list): conn_data = [conn_data]
    for conn in conn_data:
        dest_ip = conn.get('RemoteAddress')
        if dest_ip == "127.0.0.1" or dest_ip == "::1": continue
        connections.append({"destination_ip": dest_ip, "destination_port": conn.get('RemotePort'), "state": conn.get('State'), "process_name": conn.get('ProcessName'), "process_pid": conn.get('OwningProcess')})
    return connections

def discover_installed_software_windows(winrm_session):
    """Discovers installed software on a Windows host by querying the registry."""
    print("  [*] Discovering installed software (Windows)...")
    software_list = []
    paths = [
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
    ]
    for path in paths:
        cmd = f"Get-ItemProperty {path} | Where-Object {{ $_.DisplayName -ne $null }} | Select-Object DisplayName, DisplayVersion, Publisher"
        sw_data, err = execute_ps_command(winrm_session, cmd)
        if not err and sw_data:
            if not isinstance(sw_data, list): sw_data = [sw_data]
            for item in sw_data:
                software_list.append({"name": item.get('DisplayName'), "version": item.get('DisplayVersion'), "vendor": item.get('Publisher')})
    return [dict(t) for t in {tuple(d.items()) for d in software_list}]

def discover_storage_mounts_windows(winrm_session):
    """Discovers all storage volumes on a Windows host."""
    print("  [*] Discovering storage mounts (Windows)...")
    mounts = []
    cmd_vol = "Get-Volume | Select-Object DriveLetter, FileSystem, Size, SizeRemaining"
    vol_data, _ = execute_ps_command(winrm_session, cmd_vol)
    if not vol_data: return mounts
    if not isinstance(vol_data, list): vol_data = [vol_data]
    for vol in vol_data:
        drive_letter = vol.get('DriveLetter')
        if not drive_letter: continue
        storage_type = "DAS"
        fs_type = vol.get('FileSystem')
        if fs_type in ['NFS', 'ReFS', 'CSVFS']: storage_type = "NAS"
        mounts.append({
            "source": f"{drive_letter}:\\", "mount_point": f"{drive_letter}:\\",
            "filesystem_type": fs_type, "storage_type": storage_type,
            "total_gb": round(vol.get('Size', 0) / (1024**3), 2),
            "used_gb": round((vol.get('Size', 0) - vol.get('SizeRemaining', 0)) / (1024**3), 2)
        })
    return mounts

def collect_windows_perf(winrm_session, duration_minutes: int, counters: List[str], interval_seconds: int = 60):
    """Collects a detailed list of performance metrics from a Windows host."""
    if duration_minutes == 0 or not counters: return []
    print(f"[*] Starting {duration_minutes}-minute performance baseline for Windows host...")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    counter_list_str = ",".join([f'"{c}"' for c in counters])
    command = f"Get-Counter -Counter {counter_list_str} | Select-Object -ExpandProperty CounterSamples"
    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        # print(f"  [*] Collecting Windows performance data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        perf_data, err = execute_ps_command(winrm_session, command)
        if err or not perf_data:
            time.sleep(interval_seconds)
            continue
        if not isinstance(perf_data, list): perf_data = [perf_data]
        for sample in perf_data:
            try:
                path = sample.get('Path', '').lower()
                metric_base_name = path.split('\\')[-1]
                metric_name = metric_base_name.replace(' ', '_').replace('%', 'percent').replace('/', '_per_')
                instance_match = re.search(r'\((.*?)\)', metric_name)
                if instance_match:
                    instance_name = instance_match.group(1).replace(':', '').replace('#', '_')
                    instance_name = re.sub(r'[^a-zA-Z0-9_]', '_', instance_name)
                    metric_name = f"{metric_name.split('(')[0]}_{instance_name}"
                all_metrics.append({'metric_name': metric_name, 'value': round(sample.get('CookedValue', 0.0), 4), 'timestamp': collection_timestamp})
            except (ValueError, TypeError, AttributeError): continue
        time.sleep(interval_seconds)
    print(f"[*] Finished Windows performance baseline. Collected {len(all_metrics)} data points.")
    return all_metrics

def discover_scheduled_tasks_windows(winrm_session):
    """
    Discovers all enabled scheduled tasks on a Windows host.
    """
    print("  [*] Discovering scheduled tasks (Windows)...")
    tasks = []
    # Get enabled tasks and select relevant properties, including the actions
    command = "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { $_ | Select-Object -Property TaskName, TaskPath, State, @{Name='Actions';Expression={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}} }"
    task_data, err = execute_ps_command(winrm_session, command)
    
    if err or not task_data:
        return tasks
        
    if not isinstance(task_data, list):
        task_data = [task_data]

    for task in task_data:
        tasks.append({
            "name": task.get('TaskName'),
            "command": task.get('Actions'),
            "schedule": task.get('TaskPath'), # Using TaskPath as a proxy for schedule info
            "enabled": task.get('State') == 'Ready' or task.get('State') == 'Running'
        })
    return tasks

def get_all_windows_data(win_session, perf_duration, perf_interval, config_targets):
    """Wrapper to call all Windows discovery functions and bundle the data."""
    hw_data = discover_windows_hw(win_session)
    sw_data = discover_windows_sw(win_session)
    net_data = discover_windows_network(win_session)
    installed_sw = discover_installed_software_windows(win_session)
    storage_mounts = discover_storage_mounts_windows(win_session)
    config_files = [] 
    scheduled_tasks = discover_scheduled_tasks_windows(win_session)
    
    windows_counters = config_targets.get('performance_counters', {}).get('windows', [])
    perf_data = collect_windows_perf(win_session, perf_duration, windows_counters, perf_interval)
    
    return {
        **hw_data, **sw_data, "network_connections": net_data,
        "installed_software": installed_sw, "storage_mounts": storage_mounts,
        "config_files": config_files, "scheduled_tasks": scheduled_tasks
    }, perf_data