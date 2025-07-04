import paramiko
import re
from datetime import datetime
import winrm
import json
import xml.etree.ElementTree as ET

# This file will contain all functions related to connecting to hosts
# and collecting raw data.

# --- Linux Discovery Functions ---

def execute_ssh_command(ssh_client, command):
    """Executes a command on a Linux host via the given SSH client."""
    try:
        stdin, stdout, stderr = ssh_client.exec_command(command)
        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
    except Exception as e:
        print(f"Error executing SSH command '{command}': {e}")
        return "", str(e)

def discover_linux_hw(ssh_client, username):
    """
    Discovers hardware details from a Linux host using an active Paramiko connection.
    Refactored to use regular expressions for more robust parsing.

    Args:
        ssh_client (paramiko.SSHClient): An active and authenticated Paramiko SSH client.
        username (str): The username used for the connection, for logging purposes.

    Returns:
        dict: A dictionary containing the discovered hardware details.
    """
    hw_details = {}
    print("[*] Discovering Linux Hardware...")

    # --- 1. Get CPU Information using lscpu (Refactored with Regex) ---
    stdout, _ = execute_ssh_command(ssh_client, "lscpu")
    for line in stdout.splitlines():
        cpu_match = re.search(r'^CPU\(s\):\s*(\d+)', line)
        if cpu_match:
            hw_details['cpu_cores'] = int(cpu_match.group(1))
        
        model_match = re.search(r'^Model name:\s*(.*)', line)
        if model_match:
            hw_details['cpu_model'] = model_match.group(1).strip()

    # --- 2. Get System Information using dmidecode (Refactored Warning) ---
    stdout, stderr = execute_ssh_command(ssh_client, "sudo dmidecode -s system-product-name && sudo dmidecode -s system-serial-number")
    if stderr:
        print(f"  [-] Warning: Could not get system info. For full details, ensure user '{username}' has passwordless sudo rights for 'dmidecode'.")
    else:
        lines = stdout.strip().splitlines()
        if len(lines) >= 2:
            hw_details['system_model'] = lines[0].strip()
            hw_details['system_serial'] = lines[1].strip()

    # --- 3. Get Total Memory (Refactored with Regex) ---
    stdout, _ = execute_ssh_command(ssh_client, "grep MemTotal /proc/meminfo")
    mem_match = re.search(r'MemTotal:\s*(\d+)\s*kB', stdout)
    if mem_match:
        mem_kb = int(mem_match.group(1))
        hw_details['total_memory_gb'] = round(mem_kb / (1024 * 1024), 2)

    # --- 4. Get Storage Information ---
    stdout, _ = execute_ssh_command(ssh_client, "lsblk -b -d -o NAME,SIZE,TYPE")
    disks = []
    lines = stdout.strip().splitlines()
    if len(lines) > 1:
        for line in lines[1:]:
            parts = line.split()
            if 'disk' in parts:
                disks.append({'name': parts[0], 'size_gb': round(int(parts[1]) / (1024**3), 2)})
        hw_details['storage_devices'] = disks

    return hw_details

def discover_linux_sw(ssh_client):
    """Discovers software details from a Linux host."""
    sw_details = {}
    print("[*] Discovering Linux Software...")
    stdout, _ = execute_ssh_command(ssh_client, "hostname")
    sw_details['hostname'] = stdout.strip()
    stdout, _ = execute_ssh_command(ssh_client, "cat /etc/os-release")
    for line in stdout.splitlines():
        if line.startswith("PRETTY_NAME="):
            sw_details['os_name'] = line.split('=')[1].strip().strip('"')
        elif line.startswith("VERSION_ID="):
            sw_details['os_version'] = line.split('=')[1].strip().strip('"')
    stdout, _ = execute_ssh_command(ssh_client, "ps -eo user,pid,stat,comm --no-headers")
    processes = []
    for line in stdout.strip().splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            processes.append({'user': parts[0], 'pid': int(parts[1]), 'state': parts[2], 'process_name': parts[3].strip()})
    sw_details['running_processes'] = processes
    return sw_details

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
    hw_details = {}
    print("[*] Discovering Windows Hardware...")
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
    Discovers software details from a Windows host.
    Refactored to include TODO for process owner.
    """
    sw_details = {}
    print("[*] Discovering Windows Software...")
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
            processes.append({
                'process_name': proc.get('ProcessName'),
                'pid': proc.get('Id'),
                'state': proc.get('SI'),
                'user': None  # TODO: Getting process owner is a more complex query. Deferring to a future sprint.
            })
        sw_details['running_processes'] = processes
    return sw_details