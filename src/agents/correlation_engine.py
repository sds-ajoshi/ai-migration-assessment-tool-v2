# src/agents/correlation_engine.py

import sqlite3
import logging
import networkx as nx
import json
from typing import List, Dict, Any, Callable, Optional
from networkx.readwrite import json_graph

class CorrelationEngine:
    """Generates a NetworkX graph for the Digital Twin from SQLite data."""
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)

    def generate_graph_from_sqlite(self, db_path: str) -> nx.MultiDiGraph:
        """
        Generates a NetworkX graph from SQLite data.
        
        Args:
            db_path (str): Path to the SQLite database.
        
        Returns:
            nx.MultiDiGraph: Graph with nodes and relationships for the Digital Twin.
        """
        self.logger.info(f"Generating graph from SQLite database: {db_path}")
        try:
            with sqlite3.connect(db_path) as conn:
                self.conn = conn
                self.conn.row_factory = sqlite3.Row
                self._load_data()
                self._correlate()
                return self.graph
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            self.conn = None

    def export_to_graphml(self, output_path: str):
        """Exports the graph to GraphML format."""
        try:
            nx.write_graphml(self.graph, output_path)
            self.logger.info(f"Graph exported to {output_path} in GraphML format")
        except Exception as e:
            self.logger.error(f"Failed to export graph to GraphML: {e}")
            raise

    def export_to_json(self, output_path: str):
        """Exports the graph to JSON format."""
        try:
            data = json_graph.node_link_data(self.graph)
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info(f"Graph exported to {output_path} in JSON format")
        except Exception as e:
            self.logger.error(f"Failed to export graph to JSON: {e}")
            raise

    def _load_data(self):
        """Loads all necessary data from SQLite into memory."""
        self.logger.info("Loading data from SQLite...")
        self.all_servers = self._query("SELECT * FROM servers")
        self.all_apps = self._query("SELECT * FROM applications")
        self.all_software = self._query("SELECT * FROM installed_software")
        self.all_open_files = self._query("SELECT * FROM process_open_files")
        self.all_storage = self._query("SELECT * FROM storage_mounts")
        self.all_connections = self._query("SELECT * FROM network_connections")
        self.all_tasks = self._query("SELECT * FROM scheduled_tasks")
        self.all_interfaces = self._query("SELECT * FROM network_interfaces")
        self.all_metrics = self._query("SELECT * FROM performance_metrics")
        self.all_ipc = self._query("SELECT * FROM ipc_connections")
        self.server_ip_to_id = {s['ip_address']: s['id'] for s in self.all_servers}
        
        self._validate_data_quality()
        self.logger.info("Data loaded successfully.")

    def _query(self, query: str) -> List[Dict[str, Any]]:
        """Executes a SQL query and returns results as a list of dictionaries."""
        try:
            cursor = self.conn.cursor()
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            self.logger.error(f"Query failed: {query}. Error: {e}")
            raise

    def _correlate(self):
        """Runs all correlation methods in the correct order."""
        self.logger.info("Starting correlation process.")
        self._correlate_servers()
        self._correlate_processes()
        self._correlate_process_to_software()
        self._correlate_process_to_files()
        self._correlate_tasks_to_scripts()
        self._correlate_network_connections()
        self._correlate_performance_metrics()
        self._correlate_ipc_connections()
        self._correlate_network_interfaces()
        self._correlate_service_abstraction()
        self.logger.info("Correlation process complete.")

    def _validate_data_quality(self):
        """Performs data quality checks on loaded data."""
        none_packages = sum(1 for app in self.all_apps if app.get('owning_package') is None)
        if none_packages > 0:
            self.logger.warning(f"Found {none_packages} applications with NULL owning_package. This may reduce service abstraction accuracy.")
        
        invalid_states = [app['state'] for app in self.all_apps if app.get('state') and app['state'] not in ['RUNNING', 'SLEEPING', 'STOPPED']]
        if invalid_states:
            self.logger.warning(f"Found {len(invalid_states)} applications with invalid state values: {set(invalid_states)}. Expected: RUNNING, SLEEPING, STOPPED.")
        
        none_peer_ports = sum(1 for conn in self.all_connections if conn.get('peer_port') is None and conn.get('state') == 'ESTAB')
        if none_peer_ports > 0:
            self.logger.warning(f"Found {none_peer_ports} network connections with NULL peer_port in ESTAB state.")
        
        udp_connections = sum(1 for conn in self.all_connections if conn.get('protocol') == 'udp')
        if udp_connections == 0:
            self.logger.warning("No UDP connections found in network_connections table.")
        
        none_gateways = sum(1 for iface in self.all_interfaces if iface.get('gateway') is None)
        if none_gateways > 0:
            self.logger.warning(f"Found {none_gateways} network interfaces with NULL gateway.")
        
        none_dest_pids = sum(1 for ipc in self.all_ipc if not ipc.get('dest_pid'))
        if none_dest_pids > 0:
            self.logger.warning(f"Found {none_dest_pids} ipc_connections with NULL dest_pid.")

    def _add_node(self, node_id: str, node_type: str, attrs: Dict[str, Any]):
        """Helper to add a node with consistent structure."""
        self.graph.add_node(node_id, type=node_type, **attrs)

    def _add_edge(self, source: str, target: str, rel_type: str, attrs: Dict[str, Any] = {}):
        """Helper to add an edge if nodes exist."""
        if self.graph.has_node(source) and self.graph.has_node(target):
            self.graph.add_edge(source, target, type=rel_type, **attrs)
        else:
            self.logger.debug(f"Skipping edge {rel_type} from {source} to {target}: missing node(s).")

    def _correlate_servers(self):
        """Adds Server nodes."""
        self.logger.info("Correlating servers...")
        for server in self.all_servers:
            node_id = f"server_{server['id']}"
            attrs = {
                'name': server['hostname'],
                'os': server['os_name'],
                'ip': server['ip_address'],
                'server_id': server['id'],
                'cpu_cores': server.get('cpu_cores', 'N/A'),
                'total_memory_gb': server.get('total_memory_gb', 'N/A')
            }
            self._add_node(node_id, 'Server', attrs)
        self.logger.info(f"Added {len(self.all_servers)} Server nodes.")

    def _correlate_processes(self):
        """Adds Process nodes and RUNS_ON relationships."""
        self.logger.info("Correlating processes...")
        for app in self.all_apps:
            node_id = f"process_{app['server_id']}_{app['pid']}"
            attrs = {
                'name': app['process_name'],
                'server_id': app['server_id'],
                'pid': app['pid'],
                'package': app.get('owning_package', 'N/A'),
                'executable_path': app.get('executable_path', 'N/A'),
                'state': app.get('state', 'UNKNOWN')
            }
            self._add_node(node_id, 'Process', attrs)
            server_node = f"server_{app['server_id']}"
            self._add_edge(node_id, server_node, 'RUNS_ON')
        self.logger.info(f"Added {len(self.all_apps)} Process nodes.")

    def _correlate_process_to_software(self):
        """Links processes to installed software."""
        self.logger.info("Running Process-to-Software correlation...")
        for sw in self.all_software:
            node_id = f"software_{sw['id']}"
            attrs = {
                'name': sw['name'],
                'version': sw['version'],
                'server_id': sw['server_id']
            }
            self._add_node(node_id, 'InstalledSoftware', attrs)
            self._add_edge(node_id, f"server_{sw['server_id']}", 'INSTALLED_ON')
        for app in self.all_apps:
            package_name = app.get('owning_package')
            if package_name and package_name != 'N/A' and isinstance(package_name, str):
                for sw in self.all_software:
                    if sw['server_id'] == app['server_id'] and package_name in sw['name']:
                        process_node = f"process_{app['server_id']}_{app['pid']}"
                        software_node = f"software_{sw['id']}"
                        self._add_edge(process_node, software_node, 'INSTANCE_OF')
                        break
        self.logger.info("Process-to-Software correlation complete.")

    def _correlate_process_to_files(self):
        """Links processes to storage mounts they use."""
        self.logger.info("Running Process-to-Storage correlation...")
        used_storage_ids = set()
        for mount in self.all_storage:
            node_id = f"storage_{mount['id']}"
            attrs = {
                'name': mount['mount_point'],
                'mount_point': mount['mount_point'],
                'fstype': mount['filesystem_type'],
                'storage_type': mount['storage_type'],
                'server_id': mount['server_id']
            }
            self._add_node(node_id, 'StorageMount', attrs)
        for open_file in self.all_open_files:
            process_node = f"process_{open_file['server_id']}_{open_file['pid']}"
            if not self.graph.has_node(process_node):
                continue
            file_path = open_file['file_path']
            for mount in self.all_storage:
                if mount['server_id'] == open_file['server_id'] and file_path.startswith(mount['mount_point']):
                    storage_node = f"storage_{mount['id']}"
                    self._add_edge(process_node, storage_node, 'USES_STORAGE')
                    used_storage_ids.add(mount['id'])
        for mount in self.all_storage:
            if mount['id'] not in used_storage_ids:
                self._add_edge(f"storage_{mount['id']}", f"server_{mount['server_id']}", 'MOUNTED_ON')
        self.logger.info("Process-to-Storage correlation complete.")

    def _correlate_tasks_to_scripts(self):
        """Links scheduled tasks to processes."""
        self.logger.info("Running ScheduledTask correlation...")
        for task in self.all_tasks:
            node_id = f"task_{task['id']}"
            attrs = {
                'name': task['name'],
                'command': task['command'],
                'schedule': task['schedule'],
                'server_id': task['server_id']
            }
            self._add_node(node_id, 'ScheduledTask', attrs)
            self._add_edge(node_id, f"server_{task['server_id']}", 'SCHEDULED_ON')
            for app in self.all_apps:
                executable_path = app.get('executable_path')
                if executable_path and task['server_id'] == app['server_id'] and executable_path in task['command']:
                    task_node = f"task_{task['id']}"
                    process_node = f"process_{app['server_id']}_{app['pid']}"
                    self._add_edge(task_node, process_node, 'EXECUTES')
        self.logger.info("ScheduledTask correlation complete.")

    def _correlate_network_connections(self):
        """Links processes via network connections."""
        self.logger.info("Running network connection correlation...")
        server_ips = set(self.server_ip_to_id.keys())
        listening_ports = {}
        for conn in self.all_connections:
            if conn.get('local_port') and conn['state'] == 'LISTEN':
                process_node = f"process_{conn['server_id']}_{conn['pid']}"
                port_node_id = f"port_{conn['local_port']}"
                if not self.graph.has_node(port_node_id):
                    self.graph.add_node(
                        port_node_id,
                        type='Port',
                        name=str(conn['local_port']),
                        number=conn['local_port']
                    )
                if self.graph.has_node(process_node):
                    self._add_edge(process_node, port_node_id, 'LISTENS_ON')
                    listening_ports[(conn['server_id'], conn['local_port'])] = process_node
        for conn in self.all_connections:
            peer_ip = conn.get('peer_address')
            if conn.get('pid') and conn['state'] == 'ESTAB' and peer_ip and peer_ip in server_ips:
                source_process = f"process_{conn['server_id']}_{conn['pid']}"
                target_server_id = self.server_ip_to_id.get(peer_ip)
                peer_port = conn.get('peer_port')
                if peer_port is None:
                    self.logger.debug(f"Skipping COMMUNICATES_WITH for process {conn['pid']} on server {conn['server_id']}: peer_port is NULL")
                    continue
                target_process = listening_ports.get((target_server_id, peer_port))
                if target_process and self.graph.has_node(source_process) and self.graph.has_node(target_process):
                    self._add_edge(
                        source_process,
                        target_process,
                        'COMMUNICATES_WITH',
                        {'port': peer_port, 'protocol': conn.get('protocol', 'unknown')}
                    )
            elif peer_ip and peer_ip not in server_ips and peer_ip not in ['0.0.0.0', '::', '*']:
                process_node = f"process_{conn['server_id']}_{conn['pid']}"
                ext_service_node_id = f"ext_{peer_ip}"
                if not self.graph.has_node(ext_service_node_id):
                    self.graph.add_node(
                        ext_service_node_id,
                        type='ExternalService',
                        name=peer_ip,
                        ip_address=peer_ip
                    )
                if self.graph.has_node(process_node):
                    self._add_edge(
                        process_node,
                        ext_service_node_id,
                        'COMMUNICATES_WITH',
                        {'port': conn.get('peer_port', 'unknown'), 'protocol': conn.get('protocol', 'unknown')}
                    )
        self.logger.info("Network connection correlation complete.")

    def _correlate_performance_metrics(self):
        """Adds performance metrics to processes and servers."""
        self.logger.info("Running performance metrics correlation...")
        for metric in self.all_metrics:
            node_id = None
            if 'pid' in metric and metric['pid']:
                node_id = f"process_{metric['server_id']}_{metric['pid']}"
            else:
                node_id = f"server_{metric['server_id']}"
            if node_id and self.graph.has_node(node_id):
                properties = {
                    'cpu_usage_percentage': metric.get('cpu_usage_percentage', 0.0),
                    'memory_used_percent': metric.get('memory_used_percent', 0.0),
                    'disk_read_kbps': metric.get('disk_read_kbps', 0.0),
                    'disk_write_kbps': metric.get('disk_write_kbps', 0.0),
                    'net_rx_kbps': metric.get('net_rx_kbps', 0.0),
                    'net_tx_kbps': metric.get('net_tx_kbps', 0.0)
                }
                for key, value in properties.items():
                    self.graph.nodes[node_id][key] = value
        self.logger.info("Performance metrics correlation complete.")

    def _correlate_ipc_connections(self):
        """Links processes via UNIX domain sockets."""
        self.logger.info("Running IPC connection correlation...")
        ipc_count = 0
        for ipc in self.all_ipc:
            source_process = f"process_{ipc['server_id']}_{ipc['source_pid']}"
            dest_pid = ipc.get('dest_pid')
            if dest_pid:
                target_process = f"process_{ipc['server_id']}_{dest_pid}"
                if self.graph.has_node(source_process) and self.graph.has_node(target_process):
                    self._add_edge(
                        source_process,
                        target_process,
                        'IPC_WITH',
                        {'ipc_type': 'unix_socket', 'path': ipc.get('path', 'N/A')}
                    )
                    ipc_count += 1
        if ipc_count == 0:
            self.logger.warning("No IPC_WITH relationships created due to missing or invalid dest_pid values.")
        self.logger.info(f"IPC connection correlation complete. Created {ipc_count} IPC_WITH relationships.")

    def _correlate_network_interfaces(self):
        """Models network interfaces and DNS servers."""
        self.logger.info("Running network interface and DNS correlation...")
        for interface in self.all_interfaces:
            interface_node = f"interface_{interface['server_id']}_{interface['interface_name']}"
            self.graph.add_node(
                interface_node,
                type='NetworkInterface',
                name=interface['interface_name'],
                ip_address=interface.get('ip_address', 'N/A'),
                server_id=interface['server_id'],
                gateway=interface.get('gateway', 'N/A')
            )
            self.graph.add_edge(f"server_{interface['server_id']}", interface_node, type='HAS_NIC')
            dns_servers = interface.get('dns_servers', [])
            for dns_ip in dns_servers:
                dns_node = f"dns_{dns_ip}"
                self.graph.add_node(
                    dns_node,
                    type='DNSServer',
                    name=dns_ip,
                    ip_address=dns_ip
                )
                self.graph.add_edge(f"server_{interface['server_id']}", dns_node, type='USES_DNS')
        self.logger.info("Network interface and DNS correlation complete.")

    def _correlate_service_abstraction(self):
        """Groups processes into services."""
        self.logger.info("Running service abstraction correlation...")
        service_groups = {}
        for app in self.all_apps:
            package = app.get('owning_package', None)
            if package and package != 'N/A' and isinstance(package, str):
                service_name = package.lower()
                if 'apache' in service_name:
                    service_name = 'Apache Web Server'
                elif 'nginx' in service_name:
                    service_name = 'NGINX Web Server'
                elif 'mysql' in service_name or 'mariadb' in service_name:
                    service_name = 'MySQL Database'
                else:
                    service_name = package.title()
            else:
                if app.get('process_name'):
                    service_name = app['process_name'].split('/')[-1].title()
                elif app.get('executable_path'):
                    service_name = app['executable_path'].split('/')[-1].title()
                else:
                    self.logger.debug(f"Skipping service abstraction for process {app['pid']} on server {app['server_id']}: no valid package, process_name, or executable_path")
                    continue
                self.logger.debug(f"Using fallback service name '{service_name}' for process {app['pid']} on server {app['server_id']}")

            service_id = f"service_{app['server_id']}_{service_name.replace(' ', '_')}"
            if service_id not in service_groups:
                service_groups[service_id] = {
                    'name': service_name,
                    'server_id': app['server_id'],
                    'processes': []
                }
            service_groups[service_id]['processes'].append(app)

        for service_id, service_data in service_groups.items():
            self.graph.add_node(
                service_id,
                type='Service',
                name=service_data['name'],
                server_id=service_data['server_id']
            )
            self.graph.add_edge(service_id, f"server_{service_data['server_id']}", type='RUNS_ON')
            for app in service_data['processes']:
                process_node = f"process_{app['server_id']}_{app['pid']}"
                if self.graph.has_node(process_node):
                    self.graph.add_edge(process_node, service_id, type='PART_OF')
        self.logger.info(f"Service abstraction correlation complete. Created {len(service_groups)} services.")