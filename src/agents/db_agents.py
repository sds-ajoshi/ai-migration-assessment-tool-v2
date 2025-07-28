# src/agents/db_agents.py

import logging
import psycopg2
import pymysql
import cx_Oracle
import keyring
from typing import List, Dict, Any
from src.agents.base_agent import BaseIngestionAgent

logger = logging.getLogger(__name__)

class PostgreSQLAgent(BaseIngestionAgent):
    def __init__(self, host_info: Dict[str, Any], config: Dict[str, Any]):
        super().__init__(host_info, config)
        self.db_name = host_info.get('db', 'postgres')
        self.port = host_info.get('port', 5432)
        self.password = keyring.get_password("ai-migration-tool", host_info['user']) or self._get_env_password()

    def _get_env_password(self) -> str:
        import os
        return os.getenv('PG_PASSWORD', '')

    def _connect(self):
        return psycopg2.connect(
            host=self.host_info['ip'],
            port=self.port,
            database=self.db_name,
            user=self.host_info['user'],
            password=self.password
        )

    def collect_all(self) -> List[Dict[str, Any]]:
        records = []
        records.append(self._discover_os())
        records.extend(self._discover_processes())
        records.extend(self._discover_network())
        records.extend(self._discover_software())
        records.extend(self._discover_storage())
        records.extend(self._discover_perf_metrics())
        records.extend(self._discover_config_files())
        return records

    def _discover_os(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT version();")
                    version = cur.fetchone()[0]
            return {
                "type": "Database",
                "engine": "PostgreSQL",
                "version": version,
                "host": self.host_info['ip'],
                "db_name": self.db_name
            }
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL OS/version: {e}")
            return {}

    def _discover_processes(self) -> List[Dict[str, Any]]:
        # Running queries/sessions as "processes"
        sessions = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT pid, usename AS user, state, query 
                        FROM pg_stat_activity 
                        WHERE datname = current_database() AND pid <> pg_backend_pid();
                    """)
                    for row in cur.fetchall():
                        sessions.append({
                            "type": "DatabaseSession",
                            "pid": row[0],
                            "user": row[1],
                            "state": row[2],
                            "query": row[3]
                        })
            return sessions
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL sessions: {e}")
            return []

    def _discover_network(self) -> Dict[str, Any]:
        # Connections/listening ports
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT inet_server_addr(), inet_server_port();")
                    addr, port = cur.fetchone()
            return {
                "type": "NetworkConfig",
                "listen_address": addr,
                "listen_port": port
            }
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL network: {e}")
            return {}

    def _discover_software(self) -> List[Dict[str, Any]]:
        # Installed extensions
        extensions = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT name, default_version, installed_version FROM pg_available_extensions;")
                    for row in cur.fetchall():
                        extensions.append({
                            "type": "DatabaseExtension",
                            "name": row[0],
                            "default_version": row[1],
                            "installed_version": row[2]
                        })
            return extensions
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL extensions: {e}")
            return []

    def _discover_storage(self) -> List[Dict[str, Any]]:
        # Tablespaces
        tablespaces = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT spcname, pg_tablespace_location(oid) FROM pg_tablespace;")
                    for row in cur.fetchall():
                        tablespaces.append({
                            "type": "Tablespace",
                            "name": row[0],
                            "location": row[1]
                        })
            return tablespaces
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL storage: {e}")
            return []

    def _discover_perf_metrics(self) -> List[Dict[str, Any]]:
        # Basic stats
        metrics = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM pg_stat_database WHERE datname = current_database();")
                    row = cur.fetchone()
                    metrics.append({
                        "type": "PerformanceMetric",
                        "metric_name": "connections",
                        "metric_value": row[6]  # numbackends
                    })
            return metrics
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL perf metrics: {e}")
            return []

    def _discover_config_files(self) -> List[Dict[str, Any]]:
        # Config params
        configs = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT name, setting FROM pg_settings WHERE name LIKE 'listen%';")
                    for row in cur.fetchall():
                        configs.append({
                            "type": "ConfigValue",
                            "key": row[0],
                            "value": row[1]
                        })
            return configs
        except Exception as e:
            logger.error(f"Failed to discover PostgreSQL config: {e}")
            return []

class MySQLAgent(BaseIngestionAgent):
    def __init__(self, host_info: Dict[str, Any], config: Dict[str, Any]):
        super().__init__(host_info, config)
        self.db_name = host_info.get('db', 'mysql')
        self.port = host_info.get('port', 3306)
        self.password = keyring.get_password("ai-migration-tool", host_info['user']) or self._get_env_password()

    def _get_env_password(self) -> str:
        import os
        return os.getenv('MYSQL_PASSWORD', '')

    def _connect(self):
        return pymysql.connect(
            host=self.host_info['ip'],
            port=self.port,
            database=self.db_name,
            user=self.host_info['user'],
            password=self.password
        )

    def collect_all(self) -> List[Dict[str, Any]]:
        records = []
        records.append(self._discover_os())
        records.extend(self._discover_processes())
        records.extend(self._discover_network())
        records.extend(self._discover_software())
        records.extend(self._discover_storage())
        records.extend(self._discover_perf_metrics())
        records.extend(self._discover_config_files())
        return records

    def _discover_os(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT VERSION();")
                    version = cur.fetchone()[0]
            return {
                "type": "Database",
                "engine": "MySQL",
                "version": version,
                "host": self.host_info['ip'],
                "db_name": self.db_name
            }
        except Exception as e:
            logger.error(f"Failed to discover MySQL OS/version: {e}")
            return {}

    def _discover_processes(self) -> List[Dict[str, Any]]:
        sessions = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW PROCESSLIST;")
                    for row in cur.fetchall():
                        sessions.append({
                            "type": "DatabaseSession",
                            "pid": row[0],
                            "user": row[1],
                            "state": row[4],
                            "query": row[7]
                        })
            return sessions
        except Exception as e:
            logger.error(f"Failed to discover MySQL sessions: {e}")
            return []

    def _discover_network(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW GLOBAL VARIABLES LIKE 'bind_address';")
                    addr = cur.fetchone()[1]
                    cur.execute("SHOW GLOBAL VARIABLES LIKE 'port';")
                    port = cur.fetchone()[1]
            return {
                "type": "NetworkConfig",
                "listen_address": addr,
                "listen_port": int(port)
            }
        except Exception as e:
            logger.error(f"Failed to discover MySQL network: {e}")
            return {}

    def _discover_software(self) -> List[Dict[str, Any]]:
        plugins = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW PLUGINS;")
                    for row in cur.fetchall():
                        plugins.append({
                            "type": "DatabasePlugin",
                            "name": row[0],
                            "status": row[1],
                            "library": row[3]
                        })
            return plugins
        except Exception as e:
            logger.error(f"Failed to discover MySQL plugins: {e}")
            return []

    def _discover_storage(self) -> List[Dict[str, Any]]:
        engines = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW ENGINES;")
                    for row in cur.fetchall():
                        engines.append({
                            "type": "StorageEngine",
                            "name": row[0],
                            "support": row[1]
                        })
            return engines
        except Exception as e:
            logger.error(f"Failed to discover MySQL storage: {e}")
            return []

    def _discover_perf_metrics(self) -> List[Dict[str, Any]]:
        metrics = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW GLOBAL STATUS LIKE 'Threads_connected';")
                    metrics.append({
                        "type": "PerformanceMetric",
                        "metric_name": "connections",
                        "metric_value": int(cur.fetchone()[1])
                    })
            return metrics
        except Exception as e:
            logger.error(f"Failed to discover MySQL perf metrics: {e}")
            return []

    def _discover_config_files(self) -> List[Dict[str, Any]]:
        configs = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW GLOBAL VARIABLES LIKE 'port';")
                    configs.append({
                        "type": "ConfigValue",
                        "key": "port",
                        "value": cur.fetchone()[1]
                    })
            return configs
        except Exception as e:
            logger.error(f"Failed to discover MySQL config: {e}")
            return []

class OracleAgent(BaseIngestionAgent):
    def __init__(self, host_info: Dict[str, Any], config: Dict[str, Any]):
        super().__init__(host_info, config)
        self.db_name = host_info.get('db', 'ORCL')
        self.port = host_info.get('port', 1521)
        self.password = keyring.get_password("ai-migration-tool", host_info['user']) or self._get_env_password()

    def _get_env_password(self) -> str:
        import os
        return os.getenv('ORACLE_PASSWORD', '')

    def _connect(self):
        dsn = cx_Oracle.makedsn(self.host_info['ip'], self.port, service_name=self.db_name)
        return cx_Oracle.connect(user=self.host_info['user'], password=self.password, dsn=dsn)

    def collect_all(self) -> List[Dict[str, Any]]:
        records = []
        records.append(self._discover_os())
        records.extend(self._discover_processes())
        records.extend(self._discover_network())
        records.extend(self._discover_software())
        records.extend(self._discover_storage())
        records.extend(self._discover_perf_metrics())
        records.extend(self._discover_config_files())
        return records

    def _discover_os(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT * FROM v$version WHERE banner LIKE 'Oracle%'")
                    version = cur.fetchone()[0]
            return {
                "type": "Database",
                "engine": "Oracle",
                "version": version,
                "host": self.host_info['ip'],
                "db_name": self.db_name
            }
        except Exception as e:
            logger.error(f"Failed to discover Oracle OS/version: {e}")
            return {}

    def _discover_processes(self) -> List[Dict[str, Any]]:
        sessions = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT sid, username, status, sql_id FROM v$session WHERE type = 'USER'")
                    for row in cur.fetchall():
                        sessions.append({
                            "type": "DatabaseSession",
                            "pid": row[0],
                            "user": row[1],
                            "state": row[2],
                            "query": row[3]
                        })
            return sessions
        except Exception as e:
            logger.error(f"Failed to discover Oracle sessions: {e}")
            return []

    def _discover_network(self) -> Dict[str, Any]:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT value FROM v$parameter WHERE name = 'local_listener'")
                    listener = cur.fetchone()[0]
            return {
                "type": "NetworkConfig",
                "listener": listener
            }
        except Exception as e:
            logger.error(f"Failed to discover Oracle network: {e}")
            return {}

    def _discover_software(self) -> List[Dict[str, Any]]:
        components = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT comp_name, version, status FROM dba_registry")
                    for row in cur.fetchall():
                        components.append({
                            "type": "DatabaseComponent",
                            "name": row[0],
                            "version": row[1],
                            "status": row[2]
                        })
            return components
        except Exception as e:
            logger.error(f"Failed to discover Oracle components: {e}")
            return []

    def _discover_storage(self) -> List[Dict[str, Any]]:
        tablespaces = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT tablespace_name, file_name FROM dba_data_files")
                    for row in cur.fetchall():
                        tablespaces.append({
                            "type": "Tablespace",
                            "name": row[0],
                            "file_name": row[1]
                        })
            return tablespaces
        except Exception as e:
            logger.error(f"Failed to discover Oracle storage: {e}")
            return []

    def _discover_perf_metrics(self) -> List[Dict[str, Any]]:
        metrics = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM v$session WHERE status = 'ACTIVE'")
                    metrics.append({
                        "type": "PerformanceMetric",
                        "metric_name": "active_sessions",
                        "metric_value": cur.fetchone()[0]
                    })
            return metrics
        except Exception as e:
            logger.error(f"Failed to discover Oracle perf metrics: {e}")
            return []

    def _discover_config_files(self) -> List[Dict[str, Any]]:
        configs = []
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT name, value FROM v$parameter WHERE name LIKE 'spfile%'")
                    for row in cur.fetchall():
                        configs.append({
                            "type": "ConfigValue",
                            "key": row[0],
                            "value": row[1]
                        })
            return configs
        except Exception as e:
            logger.error(f"Failed to discover Oracle config: {e}")
            return []