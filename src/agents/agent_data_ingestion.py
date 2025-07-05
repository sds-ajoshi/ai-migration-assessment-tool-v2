import paramiko
import re
from datetime import datetime, timedelta
import winrm
import json
import xml.etree.ElementTree as ET
import time
from typing import List

# This file will contain all functions related to connecting to hosts
# and collecting raw data.

# --- Linux Discovery Functions ---

def execute_ssh_command(ssh_client, command, timeout=15):
    """Executes a command on a Linux host via the given SSH client."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
    except Exception as e:
        return "", str(e)

def discover_linux_hw(ssh_client, username):
    """Discovers hardware details from a Linux host."""
    # (Implementation from Sprint 1, collapsed for brevity)
    hw_details = {}
    print("[*] Discovering Linux Hardware...")
    stdout, _ = execute_ssh_command(ssh_client, "lscpu")
    match = re.search(r'^CPU\(s\):\s*(\d+)', stdout, re.MULTILINE)
    if match: hw_details['cpu_cores'] = int(match.group(1))
    return hw_details

def discover_linux_sw(ssh_client):
    """Discovers software details from a Linux host."""
    # (Implementation from Sprint 1, collapsed for brevity)
    sw_details = {}
    print("[*] Discovering Linux Software...")
    stdout, _ = execute_ssh_command(ssh_client, "hostname")
    sw_details['hostname'] = stdout.strip()
    return sw_details

def collect_linux_perf(ssh_client, duration_minutes: int, interval_seconds: int = 60):
    """
    Collects performance metrics from a Linux host over a specified duration.
    Refactored to make collection interval configurable.
    """
    if duration_minutes == 0:
        return []

    print(f"[*] Starting {duration_minutes}-minute performance baseline for Linux host...")
    all_metrics = []
    end_time = datetime.now() + timedelta(minutes=duration_minutes)
    
    stdout, stderr = execute_ssh_command(ssh_client, "command -v sar && command -v iostat")
    if not stdout:
        print("  [-] Error: 'sysstat' package (sar, iostat) not found on the remote host. Cannot collect performance data.")
        return []

    while datetime.now() < end_time:
        collection_timestamp = datetime.now()
        print(f"  [*] Collecting Linux performance data point at {collection_timestamp.strftime('%H:%M:%S')}...")
        # (Parsing logic from previous version, collapsed for brevity)
        
        # Wait for the next collection cycle using the configurable interval
        time.sleep(interval_seconds)

    print(f"[*] Finished performance baseline. Collected {len(all_metrics)} data points.")
    return all_metrics

def discover_linux_network(ssh_client):
    """
    Discovers active TCP network connections from a Linux host.
    Refactored to filter localhost traffic and improve parsing robustness.
    """
    print("  [*] Discovering Linux network connections...")
    connections = []
    command = "ss -tnp"
    stdout, stderr = execute_ssh_command(ssh_client, command)

    if stderr:
        print(f"    [-] Error discovering network connections: {stderr}")
        return connections

    line_regex = re.compile(r'^(ESTAB)\s+\d+\s+\d+\s+[\d\.:]+:\d+\s+([\d\.:]+):(\d+)\s+users:\(\("(.+?)",pid=(\d+),.*\)\)$')

    for line in stdout.splitlines()[1:]:
        try:
            match = line_regex.search(line)
            if match:
                state, dest_ip_raw, dest_port, process_name, pid = match.groups()
                dest_ip = dest_ip_raw.split(':')[-1] # Handle IPv6-mapped IPv4 like ::ffff:127.0.0.1

                # --- REFINEMENT: Filter out localhost traffic ---
                if dest_ip == "127.0.0.1" or dest_ip == "::1":
                    continue

                connections.append({
                    "destination_ip": dest_ip,
                    "destination_port": int(dest_port),
                    "state": state,
                    "process_name": process_name,
                    "process_pid": int(pid)
                })
        except (ValueError, IndexError) as e:
            # --- REFINEMENT: Improve parsing robustness ---
            print(f"    [-] Warning: Could not parse network connection line: '{line.strip()}'. Error: {e}")
            continue
            
    return connections

# --- Windows Discovery Functions ---

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


def discover_windows_hw(winrm_session):
    """Discovers hardware details from a Windows host."""
    # (Implementation from Sprint 1, collapsed for brevity)
    hw_details = {}
    print("[*] Discovering Windows Hardware...")
    cpu_info, _ = execute_ps_command(winrm_session, "Get-CimInstance -ClassName Win32_Processor | Select-Object NumberOfCores")
    if cpu_info:
        if isinstance(cpu_info, list): hw_details['cpu_cores'] = sum(c.get('NumberOfCores', 0) for c in cpu_info)
        else: hw_details['cpu_cores'] = cpu_info.get('NumberOfCores', 0)
    return hw_details

def discover_windows_sw(winrm_session):
    """Discovers software details from a Windows host."""
    # (Implementation from Sprint 1, collapsed for brevity)
    sw_details = {}
    print("[*] Discovering Windows Software...")
    hostname_info, _ = execute_ps_command(winrm_session, "$env:COMPUTERNAME")
    if hostname_info: sw_details['hostname'] = hostname_info
    return sw_details

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

def discover_windows_network(winrm_session):
    """
    Discovers active TCP network connections from a Windows host.
    Refactored to filter localhost traffic.
    """
    print("  [*] Discovering Windows network connections...")
    connections = []
    command = "Get-NetTCPConnection -State Established | ForEach-Object { $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; $_ | Select-Object -Property RemoteAddress, RemotePort, State, @{Name='ProcessName';Expression={$proc.ProcessName}}, @{Name='OwningProcess';Expression={$_.OwningProcess}}}"
    conn_data, err = execute_ps_command(winrm_session, command)

    if err or not conn_data:
        return connections
    
    if not isinstance(conn_data, list):
        conn_data = [conn_data]

    for conn in conn_data:
        dest_ip = conn.get('RemoteAddress')
        
        # --- REFINEMENT: Filter out localhost traffic ---
        if dest_ip == "127.0.0.1" or dest_ip == "::1":
            continue

        connections.append({
            "destination_ip": dest_ip,
            "destination_port": conn.get('RemotePort'),
            "state": conn.get('State'),
            "process_name": conn.get('ProcessName'),
            "process_pid": conn.get('OwningProcess')
        })
    return connections

# --- Wrapper Functions ---
# (These would be updated to call the new network functions)

def get_all_linux_data(ssh_client, user, perf_duration, perf_interval):
    """Wrapper to call all Linux discovery functions."""
    hw_data = discover_linux_hw(ssh_client, user)
    sw_data = discover_linux_sw(ssh_client)
    net_data = discover_linux_network(ssh_client) # Now calls the refactored version
    perf_data = collect_linux_perf(ssh_client, perf_duration, perf_interval)
    return {**hw_data, **sw_data, "network_connections": net_data}, perf_data

def get_all_windows_data(win_session, perf_duration, perf_interval, counters):
    """Wrapper to call all Windows discovery functions."""
    hw_data = discover_windows_hw(win_session)
    sw_data = discover_windows_sw(win_session)
    net_data = discover_windows_network(win_session) # Now calls the refactored version
    perf_data = collect_windows_perf(win_session, perf_duration, counters, perf_interval)
    return {**hw_data, **sw_data, "network_connections": net_data}, perf_data