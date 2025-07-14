# src/db/db_manager.py

import sqlite3
import logging
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

class DBManager:
    """
    Manages all interactions with the SQLite database, including schema creation
    and bulk data insertion.
    """

    def __init__(self, db_file):
        """
        Initializes the DBManager and creates a connection to the SQLite database.
        """
        self.db_file = db_file
        self.conn = None
        try:
            self.conn = sqlite3.connect(db_file, check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON;")
            logging.info(f"Successfully connected to database: {db_file}")
            self._create_tables()
        except sqlite3.Error as e:
            logging.error(f"Error connecting to database: {e}")

    def close(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()
            logging.info("Database connection closed.")

    def _create_tables(self):
        """
        Creates all necessary tables with a complete schema that includes
        all data types and foreign key constraints.
        """
        if not self.conn:
            return

        create_table_queries = [
            "CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, ip_address TEXT NOT NULL UNIQUE, os_name TEXT, os_version TEXT, cpu_cores INTEGER, total_memory_gb REAL, last_discovered_timestamp DATETIME NOT NULL);",
            """
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                process_name TEXT,
                pid INTEGER,
                user TEXT,
                state TEXT,
                command_line TEXT,
                listening_ports TEXT,
                owning_package TEXT, -- Added owning_package
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                protocol TEXT,
                state TEXT,
                local_address TEXT,
                local_port INTEGER,
                peer_address TEXT,
                peer_port INTEGER,
                process_name TEXT,
                pid INTEGER,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            "CREATE TABLE IF NOT EXISTS installed_software (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, name TEXT, version TEXT, vendor TEXT, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS storage_mounts (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, source TEXT, mount_point TEXT, filesystem_type TEXT, storage_type TEXT, total_gb REAL, used_gb REAL, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS config_files (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, file_path TEXT NOT NULL, content TEXT, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS extracted_config_pairs (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, file_path TEXT NOT NULL, key TEXT NOT NULL, value TEXT, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS scheduled_tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, name TEXT, command TEXT, schedule TEXT, enabled BOOLEAN, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS process_open_files (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, pid INTEGER NOT NULL, file_path TEXT NOT NULL, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS ipc_connections (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, source_pid INTEGER, dest_pid INTEGER, path TEXT, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS user_context (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, username TEXT, has_password BOOLEAN, shell TEXT, sudo_privileges TEXT, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);",
            "CREATE TABLE IF NOT EXISTS performance_metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER NOT NULL, metric_name TEXT, metric_value REAL, timestamp DATETIME, FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE);"
        ]
        try:
            cursor = self.conn.cursor()
            for query in create_table_queries:
                cursor.execute(query)
            self.conn.commit()
            logging.info("All tables created or already exist.")
        except sqlite3.Error as e:
            logging.error(f"Error creating tables: {e}")

    def _bulk_insert(self, query, data):
        """Generic helper for bulk insert operations."""
        if not self.conn or not data:
            return
        try:
            cursor = self.conn.cursor()
            cursor.executemany(query, data)
        except sqlite3.Error as e:
            logging.error(f"Bulk insert failed for query '{query[:30]}...': {e}")
            raise

    def add_servers_bulk(self, data):
        query = "INSERT OR REPLACE INTO servers (hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, last_discovered_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)"
        if not self.conn or not data: return
        try:
            cursor = self.conn.cursor()
            cursor.executemany(query, data)
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Bulk insert failed for servers: {e}")

    def add_applications_bulk(self, data):
        # FIXED: Added 'owning_package' to the INSERT statement
        query = "INSERT INTO applications (server_id, process_name, pid, user, state, command_line, listening_ports, owning_package) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_network_connections_bulk(self, data):
        query = "INSERT INTO network_connections (server_id, protocol, state, local_address, local_port, peer_address, peer_port, process_name, pid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_installed_software_bulk(self, data):
        query = "INSERT INTO installed_software (server_id, name, version, vendor) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_storage_mounts_bulk(self, data):
        query = "INSERT INTO storage_mounts (server_id, source, mount_point, filesystem_type, storage_type, total_gb, used_gb) VALUES (?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_config_files_bulk(self, data):
        query = "INSERT INTO config_files (server_id, file_path, content) VALUES (?, ?, ?)"
        self._bulk_insert(query, data)

    def add_extracted_config_pairs_bulk(self, data):
        query = "INSERT INTO extracted_config_pairs (server_id, file_path, key, value) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_scheduled_tasks_bulk(self, data):
        query = "INSERT INTO scheduled_tasks (server_id, name, command, schedule, enabled) VALUES (?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_process_open_files_bulk(self, data):
        query = "INSERT INTO process_open_files (server_id, pid, file_path) VALUES (?, ?, ?)"
        self._bulk_insert(query, data)

    def add_ipc_connections_bulk(self, data):
        query = "INSERT INTO ipc_connections (server_id, source_pid, dest_pid, path) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_user_context_bulk(self, data):
        query = "INSERT INTO user_context (server_id, username, has_password, shell, sudo_privileges) VALUES (?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_performance_metrics_bulk(self, data):
        query = "INSERT INTO performance_metrics (server_id, metric_name, metric_value, timestamp) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def get_server_ips_to_ids(self):
        if not self.conn: return {}
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT ip_address, id FROM servers")
            return {row[0]: row[1] for row in cursor.fetchall()}
        except sqlite3.Error as e:
            logging.error(f"Error fetching server IP map: {e}")
            return {}

    def clear_snapshot_data_for_server(self, server_id):
        if not self.conn: return
        try:
            tables = [
                "applications", "network_connections", "installed_software",
                "storage_mounts", "config_files", "extracted_config_pairs",
                "scheduled_tasks", "process_open_files", "ipc_connections",
                "user_context", "performance_metrics"
            ]
            cursor = self.conn.cursor()
            for table in tables:
                cursor.execute(f"DELETE FROM {table} WHERE server_id = ?", (server_id,))
            logging.info(f"Cleared previous snapshot data for server_id: {server_id}")
        except sqlite3.Error as e:
            logging.error(f"Error clearing snapshot data for server_id {server_id}: {e}")
            raise
    
    def get_all_servers(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM servers")
        return [dict(row) for row in cursor.fetchall()]

    def get_all_applications(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM applications")
        return [dict(row) for row in cursor.fetchall()]

    def get_all_network_connections(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM network_connections")
        return [dict(row) for row in cursor.fetchall()]
        
    def get_all_installed_software(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM installed_software")
        return [dict(row) for row in cursor.fetchall()]

    def get_all_config_files(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM config_files")
        return [dict(row) for row in cursor.fetchall()]

    def get_all_storage_mounts(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM storage_mounts")
        return [dict(row) for row in cursor.fetchall()]

    def get_all_process_open_files(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM process_open_files")
        return [dict(row) for row in cursor.fetchall()]

    def get_server_ip_by_id(self, server_id):
        if not self.conn: return None
        cursor = self.conn.cursor()
        cursor.execute("SELECT ip_address FROM servers WHERE id = ?", (server_id,))
        row = cursor.fetchone()
        return row[0] if row else None
    
    def get_all_scheduled_tasks(self):
        if not self.conn: return []
        cursor = self.conn.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute("SELECT * FROM scheduled_tasks")
        return [dict(row) for row in cursor.fetchall()]