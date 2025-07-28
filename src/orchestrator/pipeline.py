# src/orchestrator/pipeline.py

import logging
import time
from datetime import datetime
from pathlib import Path
import pandas as pd
import networkx as nx
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from src.agents.agent_data_ingestion import DataIngestionOrchestrator
from src.agents.correlation_engine import CorrelationEngine
from src.db.db_manager import DBManager
from src.db.neo4j_manager import Neo4jManager

logger = logging.getLogger(__name__)
console = Console()

class PipelineOrchestrator:
    """
    Orchestrates the ingestion, correlation, and export pipeline phases.
    """

    def __init__(self, config: Dict[str, Any], output_db: str, inventory_path: str = None, dry_run: bool = False, max_workers: int = 10):
        """
        Initializes the orchestrator with configuration and dependencies.
        
        Args:
            config: Loaded configuration dictionary.
            output_db: Path to SQLite database.
            inventory_path: Path to inventory CSV (for ingestion).
            dry_run: If True, skip actual changes.
            max_workers: Concurrency for ingestion.
        """
        self.config = config
        self.dry_run = dry_run
        self.max_workers = max_workers
        self.inventory_path = inventory_path
        self.db_manager = DBManager(output_db)
        logger.info(f"Using database: {output_db}")
        self.neo4j_config = config.get("neo4j", {})
        self.ingestion_orchestrator = DataIngestionOrchestrator(
            inventory_path=inventory_path,
            max_workers=max_workers,
            dry_run=dry_run
        ) if inventory_path else None
        self.correlation_engine = CorrelationEngine()
        self.neo4j_manager = None
        if self.neo4j_config and not dry_run:
            try:
                self.neo4j_manager = Neo4jManager(
                    uri=self.neo4j_config.get("uri"),
                    user=self.neo4j_config.get("user"),
                    password=self.neo4j_config.get("password")
                )
            except Exception as e:
                logger.error(f"Failed to initialize Neo4j manager: {e}")
                raise

    def run_ingestion(self):
        """Runs the data ingestion phase."""
        start_time = time.time()
        try:
            if not self.dry_run:
                try:
                    self.db_manager.clear_database()
                except AttributeError:
                    logger.warning("DBManager.clear_database() not found (likely deprecated); skipping DB clear and proceeding with existing data.")
            records = self.ingestion_orchestrator.collect_data()
            if not records:
                msg = "No data collected from any host. Check connectivity, credentials, or inventory."
                logger.warning(msg)
                raise ValueError(msg)
            self._persist_records(records)
            logger.info(f"Ingestion complete. Collected {len(records)} records in {time.time() - start_time:.2f} seconds.")
        except Exception as e:
            logger.error(f"Ingestion failed: {e}", exc_info=True)
            raise

    def run_correlation(self) -> nx.MultiDiGraph:
        """Runs the correlation phase to generate the graph."""
        start_time = time.time()
        try:
            graph = self.correlation_engine.generate_graph_from_sqlite(self.db_manager.db_file)
            logger.info(f"Correlation complete. Generated graph with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges in {time.time() - start_time:.2f} seconds.")
            return graph
        except Exception as e:
            logger.error(f"Correlation failed: {e}", exc_info=True)
            raise

    def run_export(self, export_graph: Optional[Path] = None):
        """Runs the export phase to Neo4j and optional file formats."""
        start_time = time.time()
        try:
            graph = self.run_correlation()
            if graph.number_of_nodes() == 0:
                logger.warning("Empty graph; skipping export.")
                return
            if self.neo4j_manager:
                self.neo4j_manager.export_graph(graph, dry_run=self.dry_run)
            if export_graph:
                nx.write_graphml(graph, export_graph)
                logger.info(f"Graph exported to {export_graph}")
            logger.info(f"Export complete in {time.time() - start_time:.2f} seconds.")
        except Exception as e:
            logger.error(f"Export failed: {e}", exc_info=True)
            raise

    def run_full_pipeline(self, export_graph: Optional[Path] = None, summary: bool = False):
        """Runs the complete pipeline: ingestion, correlation, export."""
        start_time = time.time()
        try:
            self.run_ingestion()
            self.run_export(export_graph)
            total_time = time.time() - start_time
            logger.info(f"Full pipeline complete in {total_time:.2f} seconds.")
            if summary:
                self._print_summary(total_time)
        except Exception as e:
            logger.error(f"Full pipeline failed: {e}", exc_info=True)
            raise

    def _persist_records(self, records: List[Dict[str, Any]]):
        """
        Persists collected records to the SQLite database, grouped by type.
        
        Args:
            records: List of collected records with 'type' key.
        """
        if self.dry_run:
            logger.info("Dry-run mode: Skipping persistence.")
            return

        start_time = time.time()
        try:
            from collections import defaultdict
            import sqlite3
            grouped_records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for rec in records:
                if 'type' not in rec:
                    logger.warning("Skipping record with missing 'type' key.")
                    continue
                grouped_records[rec['type']].append(rec)

            # Persist Server first to get IDs
            server_records = grouped_records.get('Server', [])
            if server_records:
                server_tuples = [
                    (
                        s.get('hostname'),
                        s.get('ip_address'),
                        s.get('os'),
                        s.get('os_version'),
                        s.get('cpu_cores'),
                        s.get('total_memory_gb'),
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    ) for s in server_records
                ]
                self.db_manager.add_servers_bulk(server_tuples)

            server_id_map = self.db_manager.get_server_ips_to_ids()

            # Persist other types with server_id
            for rec_type, rec_list in grouped_records.items():
                if rec_type == 'Server' or not rec_list:
                    continue

                # Handle missing 'id' or 'server_id' gracefully
                for r in rec_list:
                    if 'id' not in r:
                        logger.warning(f"Missing 'id' in {rec_type} record; generating temporary ID.")
                        r['id'] = f"temp_{hash(r)}_{rec_type}"

                if rec_type == 'Application':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('process_name'),
                            r.get('pid'),
                            r.get('user'),
                            r.get('state'),
                            r.get('command_line'),
                            r.get('listening_ports'),
                            r.get('owning_package')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_applications_bulk(tuples)

                elif rec_type == 'NetworkConnection':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('protocol'),
                            r.get('state'),
                            r.get('local_address'),
                            r.get('local_port'),
                            r.get('peer_address'),
                            r.get('peer_port'),
                            r.get('process_name'),
                            r.get('pid')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_network_connections_bulk(tuples)

                elif rec_type == 'InstalledSoftware':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('name'),
                            r.get('version'),
                            r.get('vendor')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_installed_software_bulk(tuples)

                elif rec_type == 'StorageMount':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('source'),
                            r.get('mount_point'),
                            r.get('filesystem_type'),
                            r.get('storage_type'),
                            r.get('total_gb'),
                            r.get('used_gb')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_storage_mounts_bulk(tuples)

                elif rec_type == 'ScheduledTask':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('name'),
                            r.get('command'),
                            r.get('schedule'),
                            r.get('enabled')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_scheduled_tasks_bulk(tuples)

                elif rec_type == 'ProcessOpenFile':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('pid'),
                            r.get('file_path')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_process_open_files_bulk(tuples)

                elif rec_type == 'IpcConnection':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('source_pid'),
                            r.get('dest_pid'),
                            r.get('path')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_ipc_connections_bulk(tuples)

                elif rec_type == 'PerformanceMetric':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('metric_name'),
                            r.get('metric_value'),
                            r.get('timestamp')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_performance_metrics_bulk(tuples)

                elif rec_type == 'NetworkInterface':
                    tuples = [
                        (
                            server_id_map.get(r.get('ip_address')),
                            r.get('interface_name'),
                            r.get('mac_address'),
                            r.get('ip_address'),
                            r.get('netmask'),
                            r.get('gateway'),
                            r.get('dns_servers')
                        ) for r in rec_list if server_id_map.get(r.get('ip_address'))
                    ]
                    self.db_manager.add_network_interfaces_bulk(tuples)

                else:
                    logger.warning(f"Unknown record type '{rec_type}' skipped during persistence.")

            persisted_count = len(records)
            logger.info(f"Persisted {persisted_count} records in {time.time() - start_time:.2f} seconds.")
        except KeyError as e:
            logger.error(f"Persistence failed due to missing key: {e}")
            raise
        except sqlite3.Error as e:
            logger.error(f"DB persistence failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during persistence: {e}", exc_info=True)
            raise

    def _print_summary(self, total_time: float):
        """Prints a summary table of pipeline results."""
        table = Table(title="Pipeline Summary")
        table.add_column("Category", style="bold")
        table.add_column("Count")

        table.add_row("Servers", str(len(self.db_manager.get_all_servers())))
        table.add_row("Applications", str(len(self.db_manager.get_all_applications())))
        table.add_row("Network Connections", str(len(self.db_manager.get_all_network_connections())))
        table.add_row("Installed Software", str(len(self.db_manager.get_all_installed_software())))
        table.add_row("Storage Mounts", str(len(self.db_manager.get_all_storage_mounts())))
        table.add_row("Scheduled Tasks", str(len(self.db_manager.get_all_scheduled_tasks())))
        table.add_row("Process Open Files", str(len(self.db_manager.get_all_process_open_files())))
        table.add_row("IPC Connections", str(len(self.db_manager.get_all_ipc_connections())))
        table.add_row("Performance Metrics", str(len(self.db_manager.get_all_performance_metrics())))
        table.add_row("Network Interfaces", str(len(self.db_manager.get_all_network_interfaces())))

        table.add_row("Total Time (s)", f"{total_time:.2f}")

        console.print(table)

    def close(self):
        """Closes all resources."""
        self.db_manager.close()
        if self.neo4j_manager:
            self.neo4j_manager.close()
        logger.info("Pipeline resources closed.")