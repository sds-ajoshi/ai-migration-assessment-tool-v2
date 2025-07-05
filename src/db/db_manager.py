import sqlite3
from sqlite3 import Error
import os
from typing import List, Tuple

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'assessment_history.db')

def create_connection():
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
    except Error as e:
        print(f"Error connecting to database: {e}")
    return conn

def create_tables(conn):
    """Create or check all necessary tables in the SQLite database."""
    sql_create_servers_table = """
    CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT NOT NULL,
        ip_address TEXT UNIQUE NOT NULL,
        os_name TEXT,
        os_version TEXT,
        cpu_cores INTEGER,
        total_memory_gb REAL,
        discovery_timestamp DATETIME NOT NULL
    );
    """
    sql_create_applications_table = """
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        process_name TEXT NOT NULL,
        pid INTEGER,
        user TEXT,
        state TEXT,
        FOREIGN KEY (server_id) REFERENCES servers (id)
    );
    """
    sql_create_performance_metrics_table = """
    CREATE TABLE IF NOT EXISTS performance_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        metric_name TEXT NOT NULL,
        metric_value REAL NOT NULL,
        timestamp DATETIME NOT NULL,
        FOREIGN KEY (server_id) REFERENCES servers (id)
    );
    """
    sql_create_network_connections_table = """
    CREATE TABLE IF NOT EXISTS network_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_server_id INTEGER NOT NULL,
        destination_ip TEXT NOT NULL,
        destination_port INTEGER NOT NULL,
        state TEXT,
        process_name TEXT,
        process_pid INTEGER,
        FOREIGN KEY (source_server_id) REFERENCES servers (id)
    );
    """
    try:
        c = conn.cursor()
        c.execute(sql_create_servers_table)
        c.execute(sql_create_applications_table)
        c.execute(sql_create_performance_metrics_table)
        c.execute(sql_create_network_connections_table)
        conn.commit()
        print("[*] All tables checked/created successfully.")
    except Error as e:
        print(f"Error creating tables: {e}")

def add_server(conn, server_data: Tuple) -> int:
    """
    Add a new server to the servers table with all its details.
    If the server IP exists, it returns the existing server's ID.
    """
    sql = '''
    INSERT INTO servers(hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, discovery_timestamp)
    VALUES(?,?,?,?,?,?,?)
    '''
    cur = conn.cursor()
    try:
        cur.execute(sql, server_data)
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        # The server already exists, let's fetch its ID.
        # We won't update it here, discovery runs are additive for connections/metrics.
        # A new full run can be done by deleting the DB file.
        cur.execute("SELECT id FROM servers WHERE ip_address = ?", (server_data[1],))
        server_id = cur.fetchone()
        if server_id:
            return server_id[0]
        return None # Should not happen if integrity error is for ip_address

def add_network_connections(conn, connections_data: List[Tuple]):
    """Add a batch of network connections to the network_connections table."""
    if not connections_data:
        return
    sql = 'INSERT INTO network_connections(source_server_id, destination_ip, destination_port, state, process_name, process_pid) VALUES(?,?,?,?,?,?)'
    cur = conn.cursor()
    cur.executemany(sql, connections_data)
    conn.commit()
    print(f"[*] Successfully inserted {len(connections_data)} network connection records.")

def add_server(conn, server_data: Tuple) -> int:
    """
    Add a new server to the servers table. If the server IP exists, return its ID.

    Args:
        conn (sqlite3.Connection): The SQLite connection object.
        server_data (tuple): A tuple containing the server's data.

    Returns:
        int: The ID of the server row.
    """
    sql = '''
    INSERT INTO servers(hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, discovery_timestamp)
    VALUES(?,?,?,?,?,?,?)
    '''
    cur = conn.cursor()
    try:
        cur.execute(sql, server_data)
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        print(f"[*] Server with IP {server_data[1]} already exists. Fetching ID.")
        cur.execute("SELECT id FROM servers WHERE ip_address = ?", (server_data[1],))
        return cur.fetchone()[0]

def add_application_process(conn, app_data: Tuple) -> int:
    """
    Add a new application process to the applications table.

    Args:
        conn (sqlite3.Connection): The SQLite connection object.
        app_data (tuple): A tuple containing the application's data.

    Returns:
        int: The ID of the newly inserted application row.
    """
    sql = '''
    INSERT INTO applications(server_id, process_name, pid, user, state)
    VALUES(?,?,?,?,?)
    '''
    cur = conn.cursor()
    cur.execute(sql, app_data)
    conn.commit()
    return cur.lastrowid

def add_performance_metrics(conn, metrics_data: List[Tuple]):
    """
    Add a batch of performance metrics to the performance_metrics table.
    Uses executemany for efficient bulk insertion.

    Args:
        conn (sqlite3.Connection): The SQLite connection object.
        metrics_data (List[Tuple]): A list of tuples, where each tuple contains:
                                     (server_id, metric_name, metric_value, timestamp)
    """
    if not metrics_data:
        return # Do nothing if there's no data

    sql = '''
    INSERT INTO performance_metrics(server_id, metric_name, metric_value, timestamp)
    VALUES(?,?,?,?)
    '''
    cur = conn.cursor()
    try:
        cur.executemany(sql, metrics_data)
        conn.commit()
        print(f"[*] Successfully inserted {len(metrics_data)} performance metric records.")
    except Error as e:
        print(f"Error bulk inserting performance metrics: {e}")


def main():
    """Main function to initialize the database and create tables."""
    print("--- Initializing Database ---")
    conn = create_connection()

    if conn is not None:
        create_tables(conn)
        conn.close()
        print("--- Database Initialized Successfully ---")
    else:
        print("!!! Error! Cannot create the database connection.")

if __name__ == '__main__':
    main()