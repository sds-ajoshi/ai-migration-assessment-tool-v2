import sqlite3
from sqlite3 import Error
import os

# Define the path for the database file in the project root
DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'assessment_history.db')

def create_connection():
    """
    Create a database connection to the SQLite database specified by DB_FILE.
    If the database file does not exist, it will be created.

    Returns:
        sqlite3.Connection: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        print(f"[*] Successful connection to SQLite DB at {DB_FILE}")
    except Error as e:
        print(f"Error connecting to database: {e}")

    return conn

def create_tables(conn):
    """
    Create the necessary tables in the SQLite database.

    This function defines and executes the SQL statements to create the 'servers'
    and 'applications' tables if they do not already exist.

    Args:
        conn (sqlite3.Connection): The SQLite connection object.
    """
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

    try:
        c = conn.cursor()
        print("[*] Creating 'servers' table...")
        c.execute(sql_create_servers_table)
        print("[*] Creating 'applications' table...")
        c.execute(sql_create_applications_table)
        conn.commit()
        print("[*] Tables created successfully.")
    except Error as e:
        print(f"Error creating tables: {e}")

def add_server(conn, server_data):
    """
    Add a new server to the servers table.

    Args:
        conn (sqlite3.Connection): The SQLite connection object.
        server_data (tuple): A tuple containing the server's data in the order:
                             (hostname, ip_address, os_name, os_version,
                              cpu_cores, total_memory_gb, discovery_timestamp)

    Returns:
        int: The ID of the newly inserted server row.
    """
    sql = '''
    INSERT INTO servers(hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, discovery_timestamp)
    VALUES(?,?,?,?,?,?,?)
    '''
    cur = conn.cursor()
    try:
        cur.execute(sql, server_data)
        conn.commit()
    except sqlite3.IntegrityError:
        # This handles the case where the IP address already exists (UNIQUE constraint)
        # We can update the existing record or just get its ID
        print(f"[*] Server with IP {server_data[1]} already exists. Fetching ID.")
        cur.execute("SELECT id FROM servers WHERE ip_address = ?", (server_data[1],))
        return cur.fetchone()[0]

    return cur.lastrowid

def add_application_process(conn, app_data):
    """
    Add a new application process to the applications table.

    Args:
        conn (sqlite3.Connection): The SQLite connection object.
        app_data (tuple): A tuple containing the application's data in the order:
                          (server_id, process_name, pid, user, state)

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