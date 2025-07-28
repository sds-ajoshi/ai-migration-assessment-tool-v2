# src/db/db_manager.py

import sqlite3
import logging
import re
from typing import List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

class DBManager:
    """
    Manages all interactions with the SQLite database, including schema creation,
    validation, and bulk data insertion for the Digital Twin platform.
    """

    def __init__(self, db_file: str):
        """
        Initializes the DBManager and creates a connection to the SQLite database.
        
        Args:
            db_file (str): Path to the SQLite database file
        """
        self.db_file = db_file
        self.conn = None
        try:
            self.conn = sqlite3.connect(db_file, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row  # Enable dict-like row access
            self.conn.execute("PRAGMA foreign_keys = ON;")
            logging.info(f"Successfully connected to database: {db_file}")
            self._create_tables()
            self._validate_schema()
        except sqlite3.Error as e:
            logging.error(f"Failed to connect to database {db_file}: {e}")
            raise

    def close(self):
        """Closes the database connection."""
        if self.conn:
            self.conn.close()
            logging.info("Database connection closed.")
            self.conn = None

    def _create_tables(self):
        """
        Creates all necessary tables with a complete schema, including indexes
        for performance and foreign key constraints for data integrity.
        """
        if not self.conn:
            return

        create_table_queries = [
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                applied_at DATETIME NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT,
                ip_address TEXT NOT NULL UNIQUE,
                os_name TEXT,
                os_version TEXT,
                cpu_cores INTEGER,
                total_memory_gb REAL,
                last_discovered_timestamp DATETIME NOT NULL
            );
            """,
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
                owning_package TEXT,
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
            """
            CREATE TABLE IF NOT EXISTS installed_software (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                name TEXT,
                version TEXT,
                vendor TEXT,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS storage_mounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                source TEXT,
                mount_point TEXT,
                filesystem_type TEXT,
                storage_type TEXT,
                total_gb REAL,
                used_gb REAL,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                name TEXT,
                command TEXT,
                schedule TEXT,
                enabled BOOLEAN,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS process_open_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS ipc_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                source_pid INTEGER,
                dest_pid INTEGER,
                path TEXT,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS network_interfaces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                interface_name TEXT NOT NULL,
                mac_address TEXT,
                ip_address TEXT,
                netmask TEXT,
                gateway TEXT,
                dns_servers TEXT,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            );
            """
        ]

        self.create_index_queries = [
            "CREATE INDEX IF NOT EXISTS idx_servers_ip ON servers (ip_address);",
            "CREATE INDEX IF NOT EXISTS idx_applications_server_id ON applications (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_network_connections_server_id ON network_connections (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_installed_software_server_id ON installed_software (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_storage_mounts_server_id ON storage_mounts (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_server_id ON scheduled_tasks (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_process_open_files_server_id ON process_open_files (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_ipc_connections_server_id ON ipc_connections (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_performance_metrics_server_id ON performance_metrics (server_id);",
            "CREATE INDEX IF NOT EXISTS idx_network_interfaces_server_id ON network_interfaces (server_id);"
        ]

        try:
            cursor = self.conn.cursor()
            for query in create_table_queries:
                cursor.execute(query)
            for query in self.create_index_queries:
                cursor.execute(query)
            # Initialize schema version if not exists
            cursor.execute("INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, datetime('now'))", ("1.0.0",))
            self.conn.commit()
            logging.info("All tables and indexes created or already exist.")
        except sqlite3.Error as e:
            logging.error(f"Error creating tables or indexes: {e}")
            raise

    def _validate_schema(self):
        """
        Validates that all required tables and indexes exist in the database.
        """
        if not self.conn:
            return
        try:
            cursor = self.conn.cursor()
            expected_tables = {
                "schema_version", "servers", "applications", "network_connections",
                "installed_software", "storage_mounts", "scheduled_tasks",
                "process_open_files", "ipc_connections",
                "performance_metrics", "network_interfaces"
            }
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            existing_tables = {row['name'] for row in cursor.fetchall()}
            missing_tables = expected_tables - existing_tables
            if missing_tables:
                logging.error(f"Missing tables: {missing_tables}")
                raise sqlite3.DatabaseError(f"Schema validation failed: missing tables {missing_tables}")

            # Validate indexes with proper regex extraction
            expected_indexes = set()
            for query in self.create_index_queries:
                match = re.search(r'idx_\w+', query)
                if match:
                    expected_indexes.add(match.group(0))
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
            existing_indexes = {row['name'] for row in cursor.fetchall()}
            missing_indexes = expected_indexes - existing_indexes
            if missing_indexes:
                logging.warning(f"Missing indexes: {missing_indexes}. Recreating...")
                for query in self.create_index_queries:
                    cursor.execute(query)
                self.conn.commit()
            logging.info("Schema validation completed successfully.")
        except sqlite3.Error as e:
            logging.error(f"Schema validation failed: {e}")
            raise

    def clear_database(self):
        """Clears all data from database tables except schema_version."""
        if not self.conn:
            return
        try:
            cursor = self.conn.cursor()
            tables = [
                "servers", "applications", "network_connections", "installed_software",
                "storage_mounts", "scheduled_tasks", "process_open_files", "ipc_connections",
                "performance_metrics", "network_interfaces"
            ]
            for table in tables:
                cursor.execute(f"DELETE FROM {table}")
            self.conn.commit()
            logging.info("Cleared all data from database tables")
        except sqlite3.Error as e:
            self.conn.rollback()
            logging.error(f"Failed to clear database: {e}")
            raise

    def _bulk_insert(self, query: str, data: List[Tuple], batch_size: int = 1000) -> None:
        """
        Generic helper for bulk insert operations with transaction handling and batching.
        
        Args:
            query (str): SQL query for insertion
            data (List[Tuple]): Data to insert
            batch_size (int): Number of rows per batch
        """
        if not self.conn or not data:
            logging.warning("No connection or empty data for bulk insert.")
            return
        try:
            cursor = self.conn.cursor()
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                cursor.executemany(query, batch)
                self.conn.commit()
                logging.debug(f"Inserted batch of {len(batch)} rows for query: {query[:30]}...")
            logging.info(f"Successfully inserted {len(data)} rows for query: {query[:30]}...")
        except sqlite3.Error as e:
            self.conn.rollback()
            logging.error(f"Bulk insert failed for query '{query[:30]}...': {e}")
            raise

    def add_servers_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert server data."""
        query = "INSERT OR REPLACE INTO servers (hostname, ip_address, os_name, os_version, cpu_cores, total_memory_gb, last_discovered_timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_applications_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert application data."""
        query = "INSERT INTO applications (server_id, process_name, pid, user, state, command_line, listening_ports, owning_package) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_network_connections_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert network connection data."""
        query = "INSERT INTO network_connections (server_id, protocol, state, local_address, local_port, peer_address, peer_port, process_name, pid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_installed_software_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert installed software data."""
        query = "INSERT INTO installed_software (server_id, name, version, vendor) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_storage_mounts_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert storage mount data."""
        query = "INSERT INTO storage_mounts (server_id, source, mount_point, filesystem_type, storage_type, total_gb, used_gb) VALUES (?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_scheduled_tasks_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert scheduled task data."""
        query = "INSERT INTO scheduled_tasks (server_id, name, command, schedule, enabled) VALUES (?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_process_open_files_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert process open files data."""
        query = "INSERT INTO process_open_files (server_id, pid, file_path) VALUES (?, ?, ?)"
        self._bulk_insert(query, data)

    def add_ipc_connections_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert IPC connection data."""
        query = "INSERT INTO ipc_connections (server_id, source_pid, dest_pid, path) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_performance_metrics_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert performance metrics data."""
        query = "INSERT INTO performance_metrics (server_id, metric_name, metric_value, timestamp) VALUES (?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def add_network_interfaces_bulk(self, data: List[Tuple]) -> None:
        """Bulk insert network interface data."""
        query = "INSERT INTO network_interfaces (server_id, interface_name, mac_address, ip_address, netmask, gateway, dns_servers) VALUES (?, ?, ?, ?, ?, ?, ?)"
        self._bulk_insert(query, data)

    def get_server_ips_to_ids(self) -> dict:
        """Retrieve mapping of server IP addresses to their IDs."""
        if not self.conn:
            return {}
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT ip_address, id FROM servers")
            return {row['ip_address']: row['id'] for row in cursor.fetchall()}
        except sqlite3.Error as e:
            logging.error(f"Error fetching server IP map: {e}")
            return {}

    def clear_snapshot_data_for_server(self, server_id: int) -> None:
        """Clear snapshot data for a specific server."""
        if not self.conn:
            return
        try:
            tables = [
                "applications", "network_connections", "installed_software",
                "storage_mounts", "scheduled_tasks", "process_open_files",
                "ipc_connections", "performance_metrics",
                "network_interfaces"
            ]
            cursor = self.conn.cursor()
            for table in tables:
                cursor.execute(f"DELETE FROM {table} WHERE server_id = ?", (server_id,))
            self.conn.commit()
            logging.info(f"Cleared previous snapshot data for server_id: {server_id}")
        except sqlite3.Error as e:
            self.conn.rollback()
            logging.error(f"Error clearing snapshot data for server_id {server_id}: {e}")
            raise

    def get_all_servers(self) -> List[dict]:
        """Retrieve all servers."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM servers")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching servers: {e}")
            return []

    def get_all_applications(self) -> List[dict]:
        """Retrieve all applications."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM applications")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching applications: {e}")
            return []

    def get_all_network_connections(self) -> List[dict]:
        """Retrieve all network connections."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM network_connections")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching network connections: {e}")
            return []

    def get_all_installed_software(self) -> List[dict]:
        """Retrieve all installed software."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM installed_software")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching installed software: {e}")
            return []

    def get_all_storage_mounts(self) -> List[dict]:
        """Retrieve all storage mounts."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM storage_mounts")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching storage mounts: {e}")
            return []

    def get_all_scheduled_tasks(self) -> List[dict]:
        """Retrieve all scheduled tasks."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM scheduled_tasks")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching scheduled tasks: {e}")
            return []

    def get_all_process_open_files(self) -> List[dict]:
        """Retrieve all process open files."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM process_open_files")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching process open files: {e}")
            return []

    def get_all_ipc_connections(self) -> List[dict]:
        """Retrieve all IPC connections."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM ipc_connections")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching IPC connections: {e}")
            return []

    def get_all_performance_metrics(self) -> List[dict]:
        """Retrieve all performance metrics."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM performance_metrics")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching performance metrics: {e}")
            return []

    def get_all_network_interfaces(self) -> List[dict]:
        """Retrieve all network interfaces."""
        if not self.conn:
            return []
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM network_interfaces")
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logging.error(f"Error fetching network interfaces: {e}")
            return []

    def get_server_ip_by_id(self, server_id: int) -> str:
        """Retrieve server IP address by ID."""
        if not self.conn:
            return None
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT ip_address FROM servers WHERE id = ?", (server_id,))
            row = cursor.fetchone()
            return row['ip_address'] if row else None
        except sqlite3.Error as e:
            logging.error(f"Error fetching server IP for server_id {server_id}: {e}")
            return None