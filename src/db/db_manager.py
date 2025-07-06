import sqlite3
from sqlite3 import Error
import os
from typing import List, Tuple, Dict

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'assessment_history.db')

def create_connection():
    """Create a database connection to the SQLite database with a higher timeout."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10.0)
    except Error as e:
        print(f"Error connecting to database: {e}")
    return conn

def create_tables(conn):
    """Create or check all necessary tables in the SQLite database."""
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL, ip_address TEXT UNIQUE NOT NULL, os_name TEXT, os_version TEXT, cpu_cores INTEGER, total_memory_gb REAL, discovery_timestamp DATETIME NOT NULL);")
    c.execute("CREATE TABLE IF NOT EXISTS applications (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, process_name TEXT NOT NULL, pid INTEGER, user TEXT, state TEXT, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS performance_metrics (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, metric_name TEXT NOT NULL, metric_value REAL NOT NULL, timestamp DATETIME NOT NULL, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS network_connections (id INTEGER PRIMARY KEY, source_server_id INTEGER NOT NULL, destination_ip TEXT NOT NULL, destination_port INTEGER NOT NULL, state TEXT, process_name TEXT, process_pid INTEGER, FOREIGN KEY (source_server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS installed_software (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, name TEXT NOT NULL, version TEXT, vendor TEXT, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS storage_mounts (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, source TEXT NOT NULL, mount_point TEXT NOT NULL, filesystem_type TEXT, storage_type TEXT, total_gb REAL, used_gb REAL, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS configuration_files (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, file_path TEXT NOT NULL, content TEXT, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS extracted_config_pairs (id INTEGER PRIMARY KEY, config_file_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT, FOREIGN KEY (config_file_id) REFERENCES configuration_files (id));")
    c.execute("CREATE TABLE IF NOT EXISTS process_open_files (id INTEGER PRIMARY KEY, application_id INTEGER NOT NULL, file_path TEXT NOT NULL, FOREIGN KEY (application_id) REFERENCES applications (id));")
    conn.commit()
    print("[*] All tables checked/created successfully.")

def add_servers_bulk(conn, server_list: List[Tuple]):
    """Adds or updates a batch of servers using a more robust INSERT/UPDATE pattern."""
    if not server_list: return
    cursor = conn.cursor()
    insert_sql = 'INSERT INTO servers(hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, discovery_timestamp) VALUES(?,?,?,?,?,?,?)'
    update_sql = 'UPDATE servers SET hostname=?, os_name=?, os_version=?, cpu_cores=?, total_memory_gb=?, discovery_timestamp=? WHERE ip_address=?'
    for server_data in server_list:
        ip_address = server_data[1]
        cursor.execute("SELECT id FROM servers WHERE ip_address = ?", (ip_address,))
        data = cursor.fetchone()
        if data is None:
            cursor.execute(insert_sql, server_data)
        else:
            update_data = (server_data[0], server_data[2], server_data[3], server_data[4], server_data[5], server_data[6], ip_address)
            cursor.execute(update_sql, update_data)
    conn.commit()
    print(f"[*] Successfully upserted {len(server_list)} server records.")

def add_applications_bulk(conn, app_list: List[Tuple]):
    """Adds a batch of application processes."""
    if not app_list: return
    sql = 'INSERT INTO applications(server_id, process_name, pid, user, state) VALUES(?,?,?,?,?)'
    conn.cursor().executemany(sql, app_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(app_list)} application process records.")

def add_performance_metrics_bulk(conn, metrics_data: List[Tuple]):
    """Adds a batch of performance metrics."""
    if not metrics_data: return
    sql = 'INSERT INTO performance_metrics(server_id, metric_name, metric_value, timestamp) VALUES(?,?,?,?)'
    conn.cursor().executemany(sql, metrics_data)
    conn.commit()
    print(f"[*] Successfully inserted {len(metrics_data)} performance metric records.")

def add_network_connections_bulk(conn, connections_data: List[Tuple]):
    """Adds a batch of network connections."""
    if not connections_data: return
    sql = 'INSERT INTO network_connections(source_server_id, destination_ip, destination_port, state, process_name, process_pid) VALUES(?,?,?,?,?,?)'
    conn.cursor().executemany(sql, connections_data)
    conn.commit()
    print(f"[*] Successfully inserted {len(connections_data)} network connection records.")

def add_installed_software_bulk(conn, software_list: List[Tuple]):
    """Adds a batch of installed software."""
    if not software_list: return
    sql = 'INSERT INTO installed_software(server_id, name, version, vendor) VALUES(?,?,?,?)'
    conn.cursor().executemany(sql, software_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(software_list)} installed software records.")

def add_storage_mounts_bulk(conn, mounts_list: List[Tuple]):
    """Adds a batch of storage mounts."""
    if not mounts_list: return
    sql = 'INSERT INTO storage_mounts(server_id, source, mount_point, filesystem_type, storage_type, total_gb, used_gb) VALUES(?,?,?,?,?,?,?)'
    conn.cursor().executemany(sql, mounts_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(mounts_list)} storage mount records.")

def add_config_files_bulk(conn, files_list: List[Tuple]):
    """Adds a batch of configuration files."""
    if not files_list: return
    sql = 'INSERT INTO configuration_files(server_id, file_path, content) VALUES(?,?,?)'
    conn.cursor().executemany(sql, files_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(files_list)} configuration file records.")

def add_open_files_bulk(conn, open_files_list: List[Tuple]):
    """Adds a batch of open file records for processes."""
    if not open_files_list: return
    sql = 'INSERT INTO process_open_files(application_id, file_path) VALUES(?,?)'
    conn.cursor().executemany(sql, open_files_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(open_files_list)} open file records.")

def get_server_ips_to_ids(conn) -> Dict[str, int]:
    """Fetches a mapping of all server IPs to their database IDs."""
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, id FROM servers")
    return {row[0]: row[1] for row in cursor.fetchall()}