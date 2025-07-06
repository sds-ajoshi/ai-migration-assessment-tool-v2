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

# --- Universal Software Inventory Discovery ---

def discover_installed_software_linux(ssh_client):
    """
    Discovers installed software on a Linux/Unix host using a multi-step fallback process.
    """
    print("  [*] Discovering installed software (Linux/Unix)...")
    software_list = []
    
    # 1. Try DPKG (Debian, Ubuntu)
    stdout, _ = execute_ssh_command(ssh_client, "command -v dpkg-query")
    if stdout:
        print("    [-] Found DPKG package manager.")
        cmd = "dpkg-query -W -f='${Package}\\t${Version}\\t${Maintainer}\\n'"
        stdout, _ = execute_ssh_command(ssh_client, cmd)
        for line in stdout.strip().splitlines():
            parts = line.split('\t')
            if len(parts) == 3:
                software_list.append({"name": parts[0], "version": parts[1], "vendor": parts[2]})
        return software_list

    # 2. Try RPM (CentOS, RHEL, Fedora)
    stdout, _ = execute_ssh_command(ssh_client, "command -v rpm")
    if stdout:
        print("    [-] Found RPM package manager.")
        cmd = "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\n'"
        stdout, _ = execute_ssh_command(ssh_client, cmd)
        for line in stdout.strip().splitlines():
            parts = line.split('\t')
            if len(parts) == 3:
                software_list.append({"name": parts[0], "version": parts[1], "vendor": parts[2]})
        return software_list

    # 3. Try pkginfo (Solaris)
    stdout, _ = execute_ssh_command(ssh_client, "command -v pkginfo")
    if stdout:
        print("    [-] Found pkginfo package manager (Solaris).")
        cmd = "pkginfo -l"
        stdout, _ = execute_ssh_command(ssh_client, cmd)
        # Solaris pkginfo -l parsing is complex and stateful, requires more specific logic
        # For now, we acknowledge detection but defer full implementation.
        print("    [!] Solaris pkginfo parsing is not yet fully implemented.")
        return software_list

    # 4. Try lslpp (AIX)
    stdout, _ = execute_ssh_command(ssh_client, "command -v lslpp")
    if stdout:
        print("    [-] Found lslpp package manager (AIX).")
        cmd = "lslpp -L -c"
        stdout, _ = execute_ssh_command(ssh_client, cmd)
        # AIX lslpp parsing
        print("    [!] AIX lslpp parsing is not yet fully implemented.")
        return software_list

    # 5. Fallback: Scan PATH
    print("    [-] No known package manager found. Falling back to PATH scan (best-effort).")
    # This is a very basic fallback and can be expanded
    cmd = "ls -F /usr/bin/ /bin/ /usr/sbin/ /sbin/"
    stdout, _ = execute_ssh_command(ssh_client, cmd)
    for line in stdout.splitlines():
        if line.endswith('*') and not line.endswith('/'):
            software_list.append({"name": line.strip('*'), "version": "N/A (Executable)", "vendor": "N/A"})
    
    return software_list

def discover_config_files(ssh_client, config_targets: List[Dict]):
    """
    Finds, downloads, and parses configuration files based on targets
    defined in the knowledge base.
    """
    print("  [*] Discovering application configuration files...")
    discovered_files = []
    
    if not config_targets:
        return discovered_files

    for target in config_targets:
        target_name = target.get("name")
        search_paths = " ".join(target.get("paths", ["/etc"]))
        
        # 1. Find the file(s)
        find_cmd = f"find {search_paths} -name {target_name} -type f 2>/dev/null"
        found_paths_str, err = execute_ssh_command(ssh_client, find_cmd)
        if err:
            continue

        for file_path in found_paths_str.strip().splitlines():
            print(f"    [-] Found potential config file: {file_path}")
            content = ""
            
            # 2. Try to read the file normally
            cat_cmd = f"cat {file_path}"
            content, cat_err = execute_ssh_command(ssh_client, cat_cmd)
            
            # 3. If permission denied, try with sudo
            if "Permission denied" in cat_err:
                print(f"    [!] Permission denied for {file_path}. Trying with sudo...")
                sudo_cat_cmd = f"sudo cat {file_path}"
                content, sudo_err = execute_ssh_command(ssh_client, sudo_cat_cmd)
                if sudo_err:
                    print(f"    [-] Failed to read with sudo: {sudo_err.strip()}")
                    content = f"Error: Could not read file. Sudo failed: {sudo_err.strip()}"

            # 4. Parse the content if parsers are defined
            extracted_pairs = []
            if "parsers" in target and content:
                for parser in target["parsers"]:
                    try:
                        # Simple regex for now, can be expanded for section-based parsing
                        match = re.search(parser["regex"], content, re.MULTILINE)
                        if match:
                            extracted_pairs.append({
                                "key": parser["key"],
                                "value": match.group(1).strip()
                            })
                    except re.error as e:
                        print(f"    [-] Invalid regex for key '{parser['key']}': {e}")
            
            discovered_files.append({
                "file_path": file_path,
                "content": content, # For now, we store the full content
                "extracted_pairs": extracted_pairs
            })

    return discovered_files

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
    """Discovers software details from a Linux host."""
    sw_details = {}
    print("  [*] Discovering Linux Software...")
    stdout, _ = execute_ssh_command(ssh_client, "hostname")
    sw_details['hostname'] = stdout.strip()
    stdout, _ = execute_ssh_command(ssh_client, "cat /etc/os-release")
    for line in stdout.splitlines():
        if line.startswith("PRETTY_NAME="): sw_details['os_name'] = line.split('=')[1].strip().strip('"')
        elif line.startswith("VERSION_ID="): sw_details['os_version'] = line.split('=')[1].strip().strip('"')
    stdout, _ = execute_ssh_command(ssh_client, "ps -eo user,pid,stat,comm --no-headers")
    processes = []
    for line in stdout.strip().splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            processes.append({'user': parts[0], 'pid': int(parts[1]), 'state': parts[2], 'process_name': parts[3].strip()})
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

def _parse_proc_stat(stdout: str) -> Dict:
    """Helper to parse the first line of /proc/stat."""
    parts = stdout.splitlines()[0].split()
    cpu_times = [int(p) for p in parts[1:]]
    return {'user': cpu_times[0], 'nice': cpu_times[1], 'system': cpu_times[2], 'idle': cpu_times[3], 'iowait': cpu_times[4], 'total': sum(cpu_times)}

def _collect_perf_from_proc(ssh_client, duration_minutes, interval_seconds):
    """Fallback performance collection method using the /proc filesystem."""
    print("  [*] 'sysstat' not found. Using fallback performance collection from /proc.")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    stdout, _ = execute_ssh_command(ssh_client, "cat /proc/stat")
    if not stdout: return []
    last_cpu_stats = _parse_proc_stat(stdout)

    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        print(f"  [*] Collecting /proc data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        stdout, _ = execute_ssh_command(ssh_client, "cat /proc/stat")
        if stdout:
            current_cpu_stats = _parse_proc_stat(stdout)
            delta_total = current_cpu_stats['total'] - last_cpu_stats['total']
            delta_idle = current_cpu_stats['idle'] - last_cpu_stats['idle']
            if delta_total > 0:
                cpu_util = 100.0 * (1.0 - (delta_idle / delta_total))
                all_metrics.append({'metric_name': 'cpu_percent_utilization', 'value': round(cpu_util, 2), 'timestamp': collection_timestamp})
            last_cpu_stats = current_cpu_stats
        stdout, _ = execute_ssh_command(ssh_client, "cat /proc/meminfo")
        if stdout:
            mem_total = mem_available = 0
            for line in stdout.splitlines():
                if line.startswith("MemTotal:"): mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:"): mem_available = int(line.split()[1])
            if mem_total > 0:
                mem_used = 100.0 * ((mem_total - mem_available) / mem_total)
                all_metrics.append({'metric_name': 'memory_percent_used', 'value': round(mem_used, 2), 'timestamp': collection_timestamp})
        time.sleep(interval_seconds)
    return all_metrics

def _collect_perf_with_sysstat(ssh_client, duration_minutes, interval_seconds):
    """Primary performance collection method using sar/iostat."""
    print("  [*] 'sysstat' package found. Using 'sar' and 'iostat' for collection.")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        print(f"  [*] Collecting sysstat data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        # --- Added full implementation for CPU and Memory ---
        # CPU Usage with sar
        stdout, _ = execute_ssh_command(ssh_client, "sar -u 1 1")
        lines = stdout.strip().splitlines()
        if len(lines) > 2 and lines[-1].split()[1] == 'all':
            cpu_idle = float(lines[-1].split()[-1])
            all_metrics.append({'metric_name': 'cpu_percent_utilization', 'value': round(100.0 - cpu_idle, 2), 'timestamp': collection_timestamp})

        # Memory Usage with sar
        stdout, _ = execute_ssh_command(ssh_client, "sar -r 1 1")
        lines = stdout.strip().splitlines()
        if len(lines) > 2:
            try:
                mem_used_percent = float(lines[-1].split()[3])
                all_metrics.append({'metric_name': 'memory_percent_used', 'value': mem_used_percent, 'timestamp': collection_timestamp})
            except (ValueError, IndexError):
                pass # Ignore parsing errors for this data point
        
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

# --- NEW: Comprehensive Storage Discovery ---

def discover_storage_mounts_linux(ssh_client):
    """
    Discovers all storage mounts on a Linux host, identifying DAS, NAS, and SAN.
    """
    print("  [*] Discovering storage mounts (Linux)...")
    mounts = []
    
    # 1. Get SAN device paths from multipath, if available
    san_devices = set()
    stdout, _ = execute_ssh_command(ssh_client, "command -v multipath")
    if stdout:
        print("    [-] Found multipath tools, checking for SAN LUNs...")
        mp_stdout, _ = execute_ssh_command(ssh_client, "multipath -ll")
        # Regex to find device mapper names like 'dm-2'
        for line in mp_stdout.splitlines():
            match = re.search(r'\((\w+)\)\s+dm-\d+', line)
            if match:
                san_devices.add(f"/dev/mapper/{match.group(1)}")

    # 2. Get all mount points and their types
    # Using -P to prevent line wrapping
    # GNU coreutils does not allow -T/-P with --output at the same time
    # Keep the custom column list and drop the other flags.
    df_cmd = "df --output=source,fstype,size,used,target"
    df_stdout, _ = execute_ssh_command(ssh_client, df_cmd)
    
    for line in df_stdout.strip().splitlines()[1:]: # Skip header
        parts = line.split()
        if not parts: continue
        source, fs_type, total_kb, used_kb, mount_point = parts[0], parts[1], parts[2], parts[3], parts[4]

        # Determine storage type
        storage_type = "DAS" # Default to Direct-Attached Storage
        if fs_type.startswith("nfs") or fs_type == "cifs":
            storage_type = "NAS"
        elif source in san_devices:
            storage_type = "SAN"

        try:
            mounts.append({
                "source": source,
                "mount_point": mount_point,
                "filesystem_type": fs_type,
                "storage_type": storage_type,
                "total_gb": round(int(total_kb) / (1024*1024), 2),
                "used_gb": round(int(used_kb) / (1024*1024), 2)
            })
        except ValueError:
            continue # Skip lines that don't parse correctly (like headers)
            
    return mounts

def discover_process_open_files(ssh_client, pids: List[int]):
    """
    For a given list of Process IDs, find all open files using lsof.
    """
    if not pids:
        return {}
    
    print("  [*] Discovering open files for running processes...")
    # Create a single command to check all PIDs at once for efficiency
    pid_str = ",".join(map(str, pids))
    command = f"lsof -p {pid_str} -n -P | awk '{{print $2, $9}}'"
    stdout, _ = execute_ssh_command(ssh_client, command)

    open_files_map = defaultdict(list)
    for line in stdout.strip().splitlines():
        try:
            pid, file_path = line.split(maxsplit=1)
            # We only care about absolute paths to files, not sockets or pipes
            if file_path.startswith('/'):
                open_files_map[int(pid)].append(file_path)
        except ValueError:
            continue
            
    return open_files_map

def get_all_linux_data(ssh_client, user, perf_duration, perf_interval, config_targets):
    """Wrapper to call all Linux discovery functions and bundle the data."""
    hw_data = discover_linux_hw(ssh_client, user)
    sw_data = discover_linux_sw(ssh_client)
    net_data = discover_linux_network(ssh_client)
    installed_sw = discover_installed_software_linux(ssh_client)
    storage_mounts = discover_storage_mounts_linux(ssh_client)
    config_files = discover_config_files(ssh_client, config_targets)
    
    running_pids = [p['pid'] for p in sw_data.get('running_processes', [])]
    open_files_map = discover_process_open_files(ssh_client, running_pids)
    for proc in sw_data.get('running_processes', []):
        proc['open_files'] = open_files_map.get(proc['pid'], [])

    perf_data = collect_linux_perf(ssh_client, perf_duration, perf_interval)
    
    return {
        **hw_data, 
        **sw_data, 
        "network_connections": net_data,
        "installed_software": installed_sw,
        "storage_mounts": storage_mounts,
        "config_files": config_files
    }, perf_data

def discover_installed_software_windows(winrm_session):
    """
    Discovers installed software on a Windows host by querying the registry.
    """
    print("  [*] Discovering installed software (Windows)...")
    software_list = []
    # Query both 32-bit and 64-bit uninstall keys
    paths = [
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
    ]
    for path in paths:
        cmd = f"Get-ItemProperty {path} | Where-Object {{ $_.DisplayName -ne $null }} | Select-Object DisplayName, DisplayVersion, Publisher"
        sw_data, err = execute_ps_command(winrm_session, cmd)
        if not err and sw_data:
            if not isinstance(sw_data, list):
                sw_data = [sw_data]
            for item in sw_data:
                software_list.append({
                    "name": item.get('DisplayName'),
                    "version": item.get('DisplayVersion'),
                    "vendor": item.get('Publisher')
                })
    # Remove duplicates that might appear in both hives
    return [dict(t) for t in {tuple(d.items()) for d in software_list}]

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
    """Discovers software details from a Windows host."""
    sw_details = {}
    print("  [*] Discovering Windows Software...")
    hostname_info, _ = execute_ps_command(winrm_session, "$env:COMPUTERNAME")
    if hostname_info: sw_details['hostname'] = hostname_info
    os_info, _ = execute_ps_command(winrm_session, "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version")
    if os_info:
        sw_details['os_name'] = os_info.get('Caption')
        sw_details['os_version'] = os_info.get('Version')
    proc_info, _ = execute_ps_command(winrm_session, "Get-Process | Select-Object ProcessName, Id, SI")
    if proc_info:
        processes = []
        for proc in proc_info:
            processes.append({'process_name': proc.get('ProcessName'), 'pid': proc.get('Id'), 'state': proc.get('SI'), 'user': None})
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

def collect_windows_perf(winrm_session, duration_minutes: int, counters: List[str], interval_seconds: int = 60):
    """
    Collects performance metrics from a Windows host over a specified duration.
    Refactored to accept a list of counters and a configurable interval.
    """
    if duration_minutes == 0 or not counters:
        return []

    print(f"[*] Starting {duration_minutes}-minute performance baseline for Windows host...")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)

    # Format the counter list (provided as a parameter) for the Get-Counter command
    counter_list_str = ",".join([f'"{c}"' for c in counters])

    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        print(f"  [*] Collecting Windows performance data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        
        command = f"Get-Counter -Counter {counter_list_str} | Select-Object -ExpandProperty CounterSamples"
        perf_data, err = execute_ps_command(winrm_session, command)

        if err:
            print(f"  [-] Error collecting performance counters: {err}")
            time.sleep(interval_seconds)
            continue
        
        if not perf_data:
            time.sleep(interval_seconds)
            continue
            
        if not isinstance(perf_data, list):
            perf_data = [perf_data]

        for sample in perf_data:
            path = sample.get('Path', '').lower()
            metric_name = path.split('\\')[-1].replace(' ', '_').replace('%', 'percent')
            instance_match = re.search(r'\((.*?)\)', path)
            if instance_match:
                instance_name = instance_match.group(1).replace(':', '')
                metric_name = f"{metric_name.split('(')[0]}_{instance_name}"

            all_metrics.append({
                'metric_name': metric_name,
                'value': round(sample.get('CookedValue', 0.0), 4),
                'timestamp': collection_timestamp
            })
        
        # Wait for the next collection cycle using the configurable interval
        time.sleep(interval_seconds)

    print(f"[*] Finished performance baseline. Collected {len(all_metrics)} data points.")
    return all_metrics

def discover_storage_mounts_windows(winrm_session):
    """
    Discovers all storage volumes on a Windows host, identifying DAS, NAS, and SAN.
    """
    print("  [*] Discovering storage mounts (Windows)...")
    mounts = []
    
    # 1. Check for iSCSI connections (SAN)
    iscsi_disks = set()
    cmd_iscsi = "Get-WmiObject -Namespace root\\wmi -ClassName MSiSCSIInitiator_SessionClass | ForEach-Object { $_.Devices.DeviceNumber }"
    iscsi_data, _ = execute_ps_command(winrm_session, cmd_iscsi)
    if iscsi_data:
        if not isinstance(iscsi_data, list): iscsi_data = [iscsi_data]
        iscsi_disks.update(iscsi_data)

    # 2. Get all volumes
    cmd_vol = "Get-Volume | Select-Object DriveLetter, FileSystem, Size, SizeRemaining"
    vol_data, _ = execute_ps_command(winrm_session, cmd_vol)
    if not vol_data: return mounts
    if not isinstance(vol_data, list): vol_data = [vol_data]

    for vol in vol_data:
        drive_letter = vol.get('DriveLetter')
        if not drive_letter: continue

        # Determine storage type
        storage_type = "DAS" # Default
        fs_type = vol.get('FileSystem')
        if fs_type in ['NFS', 'ReFS', 'CSVFS']: # Common network filesystems
            storage_type = "NAS"
        
        # Check if this disk is an iSCSI LUN
        # This requires correlating drive letter to disk number, which is complex.
        # For now, we'll placeholder this logic. A more advanced script would be needed.
        # if disk_number in iscsi_disks: storage_type = "SAN"

        mounts.append({
            "source": f"{drive_letter}:\\",
            "mount_point": f"{drive_letter}:\\",
            "filesystem_type": fs_type,
            "storage_type": storage_type,
            "total_gb": round(vol.get('Size', 0) / (1024**3), 2),
            "used_gb": round((vol.get('Size', 0) - vol.get('SizeRemaining', 0)) / (1024**3), 2)
        })
    return mounts

def get_all_windows_data(win_session, perf_duration, perf_interval, config_targets):
    """Wrapper to call all Windows discovery functions and bundle the data."""
    hw_data = discover_windows_hw(win_session)
    sw_data = discover_windows_sw(win_session)
    net_data = discover_windows_network(win_session)
    installed_sw = discover_installed_software_windows(win_session)
    storage_mounts = discover_storage_mounts_windows(win_session)
    # Windows config file discovery would go here
    perf_data = collect_windows_perf(win_session, perf_duration, [], perf_interval)

    return {
        **hw_data, 
        **sw_data, 
        "network_connections": net_data,
        "installed_software": installed_sw,
        "storage_mounts": storage_mounts,
        "config_files": []
    }, perf_data
