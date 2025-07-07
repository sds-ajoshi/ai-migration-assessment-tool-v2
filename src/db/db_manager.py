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
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY,
        hostname TEXT NOT NULL,
        ip_address TEXT UNIQUE NOT NULL,
        os_name TEXT,
        os_version TEXT,
        cpu_cores INTEGER,
        total_memory_gb REAL,
        discovery_timestamp DATETIME NOT NULL
    );
    """)
    
    c.execute("""
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY,
        server_id INTEGER NOT NULL,
        process_name TEXT NOT NULL,
        pid INTEGER,
        user TEXT,
        state TEXT,
        command_line TEXT,
        FOREIGN KEY (server_id) REFERENCES servers (id)
    );
    """)
    
    c.execute("CREATE TABLE IF NOT EXISTS performance_metrics (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, metric_name TEXT NOT NULL, metric_value REAL NOT NULL, timestamp DATETIME NOT NULL, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS network_connections (id INTEGER PRIMARY KEY, source_server_id INTEGER NOT NULL, destination_ip TEXT NOT NULL, destination_port INTEGER NOT NULL, state TEXT, process_name TEXT, process_pid INTEGER, FOREIGN KEY (source_server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS installed_software (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, name TEXT NOT NULL, version TEXT, vendor TEXT, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS storage_mounts (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, source TEXT NOT NULL, mount_point TEXT NOT NULL, filesystem_type TEXT, storage_type TEXT, total_gb REAL, used_gb REAL, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS configuration_files (id INTEGER PRIMARY KEY, server_id INTEGER NOT NULL, file_path TEXT NOT NULL, content TEXT, FOREIGN KEY (server_id) REFERENCES servers (id));")
    c.execute("CREATE TABLE IF NOT EXISTS extracted_config_pairs (id INTEGER PRIMARY KEY, config_file_id INTEGER NOT NULL, key TEXT NOT NULL, value TEXT, FOREIGN KEY (config_file_id) REFERENCES configuration_files (id));")
    c.execute("CREATE TABLE IF NOT EXISTS process_open_files (id INTEGER PRIMARY KEY, application_id INTEGER NOT NULL, file_path TEXT NOT NULL, FOREIGN KEY (application_id) REFERENCES applications (id));")
    c.execute("CREATE TABLE IF NOT EXISTS application_config_map (application_id INTEGER NOT NULL, config_file_id INTEGER NOT NULL, PRIMARY KEY (application_id, config_file_id), FOREIGN KEY (application_id) REFERENCES applications (id), FOREIGN KEY (config_file_id) REFERENCES configuration_files (id));")

    print("[*] Creating 'scheduled_tasks' table...")
    c.execute("""
    CREATE TABLE IF NOT EXISTS scheduled_tasks (
        id INTEGER PRIMARY KEY,
        server_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        command TEXT NOT NULL,
        schedule TEXT,
        enabled BOOLEAN,
        FOREIGN KEY (server_id) REFERENCES servers (id)
    );
    """)

    print("[*] Creating 'ipc_connections' table...")
    c.execute("""
    CREATE TABLE IF NOT EXISTS ipc_connections (
        id INTEGER PRIMARY KEY,
        server_id INTEGER NOT NULL,
        source_pid INTEGER NOT NULL,
        dest_pid INTEGER NOT NULL,
        path TEXT,
        FOREIGN KEY (server_id) REFERENCES servers (id)
    );
    """)

    conn.commit()
    print("[*] All tables checked/created successfully.")

def clear_snapshot_data_for_server(conn, server_id: int):
    """
    Deletes all state-based data for a given server_id before new data is inserted.
    """
    cursor = conn.cursor()
    print(f"[*] Clearing old snapshot data for server_id: {server_id}")
    
    app_ids_to_delete = [row[0] for row in cursor.execute("SELECT id FROM applications WHERE server_id = ?", (server_id,)).fetchall()]
    if app_ids_to_delete:
        cursor.executemany("DELETE FROM process_open_files WHERE application_id = ?", [(app_id,) for app_id in app_ids_to_delete])
        cursor.executemany("DELETE FROM application_config_map WHERE application_id = ?", [(app_id,) for app_id in app_ids_to_delete])

    cursor.execute("DELETE FROM applications WHERE server_id = ?", (server_id,))
    cursor.execute("DELETE FROM network_connections WHERE source_server_id = ?", (server_id,))
    cursor.execute("DELETE FROM installed_software WHERE server_id = ?", (server_id,))
    cursor.execute("DELETE FROM storage_mounts WHERE server_id = ?", (server_id,))
    cursor.execute("DELETE FROM configuration_files WHERE server_id = ?", (server_id,))
    cursor.execute("DELETE FROM scheduled_tasks WHERE server_id = ?", (server_id,))
    cursor.execute("DELETE FROM ipc_connections WHERE server_id = ?", (server_id,))
    
    conn.commit()

def add_servers_bulk(conn, server_list: List[Tuple]):
    """Adds or updates a batch of servers."""
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
    sql = 'INSERT INTO applications(server_id, process_name, pid, user, state, command_line) VALUES(?,?,?,?,?,?)'
    conn.cursor().executemany(sql, app_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(app_list)} application process records.")

def add_scheduled_tasks_bulk(conn, tasks_list: List[Tuple]):
    """Adds a batch of scheduled tasks."""
    if not tasks_list: return
    sql = 'INSERT INTO scheduled_tasks(server_id, name, command, schedule, enabled) VALUES(?,?,?,?,?)'
    conn.cursor().executemany(sql, tasks_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(tasks_list)} scheduled task records.")

def add_ipc_connections_bulk(conn, ipc_list: List[Tuple]):
    """Adds a batch of Inter-Process Communication connections."""
    if not ipc_list: return
    sql = 'INSERT INTO ipc_connections(server_id, source_pid, dest_pid, path) VALUES(?,?,?,?)'
    conn.cursor().executemany(sql, ipc_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(ipc_list)} IPC connection records.")

# (Other bulk add functions remain unchanged)
def add_performance_metrics_bulk(conn, metrics_data: List[Tuple]):
    if not metrics_data: return
    conn.cursor().executemany('INSERT INTO performance_metrics(server_id, metric_name, metric_value, timestamp) VALUES(?,?,?,?)', metrics_data)
    conn.commit()
    print(f"[*] Successfully inserted {len(metrics_data)} performance metric records.")
def add_network_connections_bulk(conn, connections_data: List[Tuple]):
    if not connections_data: return
    conn.cursor().executemany('INSERT INTO network_connections(source_server_id, destination_ip, destination_port, state, process_name, process_pid) VALUES(?,?,?,?,?,?)', connections_data)
    conn.commit()
    print(f"[*] Successfully inserted {len(connections_data)} network connection records.")
def add_installed_software_bulk(conn, software_list: List[Tuple]):
    if not software_list: return
    conn.cursor().executemany('INSERT INTO installed_software(server_id, name, version, vendor) VALUES(?,?,?,?)', software_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(software_list)} installed software records.")
def add_storage_mounts_bulk(conn, mounts_list: List[Tuple]):
    if not mounts_list: return
    conn.cursor().executemany('INSERT INTO storage_mounts(server_id, source, mount_point, filesystem_type, storage_type, total_gb, used_gb) VALUES(?,?,?,?,?,?,?)', mounts_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(mounts_list)} storage mount records.")
def add_config_files_bulk(conn, files_list: List[Tuple]):
    if not files_list: return
    conn.cursor().executemany('INSERT INTO configuration_files(server_id, file_path, content) VALUES(?,?,?)', files_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(files_list)} configuration file records.")
def add_open_files_bulk(conn, open_files_list: List[Tuple]):
    if not open_files_list: return
    conn.cursor().executemany('INSERT INTO process_open_files(application_id, file_path) VALUES(?,?)', open_files_list)
    conn.commit()
    print(f"[*] Successfully inserted {len(open_files_list)} open file records.")

def get_server_ips_to_ids(conn) -> Dict[str, int]:
    """Fetches a mapping of all server IPs to their database IDs."""
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, id FROM servers")
    return {row[0]: row[1] for row in cursor.fetchall()}