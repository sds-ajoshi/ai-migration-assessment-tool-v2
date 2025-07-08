# src/agents/agent_profiling.py

import os
import networkx as nx
from networkx.algorithms import community
import logging
from collections import defaultdict
import shlex
import time
import json
import subprocess
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')


class CorrelationEngine:
    """
    Enriches the base Digital Twin graph by creating deep, contextual relationships
    between processes, software, configuration files, and storage.
    """

    def __init__(self, db_manager):
        """
        Initializes the CorrelationEngine and pre-loads all necessary data
        from the database into memory for efficient processing.
        """
        self.db_manager = db_manager
        self._load_data_into_memory()

    def _load_data_into_memory(self):
        """
        Fetches all correlation-related data from the database once and organizes
        it in memory for fast lookups.
        """
        logging.info("CorrelationEngine: Starting to load and pre-process data from database into memory...")
        start_time = time.time()
        
        try:
            # Create a map of installed software for each server: {(server_id, software_name): software_details}
            self.software_map = {}
            installed_software = self.db_manager.get_all_installed_software()
            for sw in installed_software:
                self.software_map[(sw['server_id'], sw['name'])] = sw

            self.config_files_set = defaultdict(set)
            config_files = self.db_manager.get_all_config_files()
            for cf in config_files:
                self.config_files_set[cf['server_id']].add(cf['file_path'])

            self.storage_mounts = defaultdict(list)
            storage_mounts = self.db_manager.get_all_storage_mounts()
            for sm in storage_mounts:
                self.storage_mounts[sm['server_id']].append(sm)
            for server_id in self.storage_mounts:
                self.storage_mounts[server_id].sort(key=lambda x: len(x['mount_point']), reverse=True)

            self.open_files_map = defaultdict(lambda: defaultdict(list))
            open_files = self.db_manager.get_all_process_open_files()
            for of in open_files:
                self.open_files_map[of['server_id']][of['pid']].append(of['file_path'])

        except AttributeError as e:
            logging.warning(f"CorrelationEngine: Could not load all data. DBManager might be missing methods for new data types. Error: {e}")
            self.software_map = {}
            self.config_files_set = defaultdict(set)
            self.storage_mounts = defaultdict(list)
            self.open_files_map = defaultdict(lambda: defaultdict(list))
        
        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"CorrelationEngine: Data loaded successfully in {duration:.2f} seconds.")


    def run_correlation(self, graph):
        """
        Orchestrates the entire correlation process, enriching the provided graph.
        """
        logging.info("CorrelationEngine: Starting correlation process.")
        graph = self._correlate_process_to_software(graph)
        graph = self._correlate_process_to_config_and_storage(graph)
        logging.info("CorrelationEngine: Correlation process complete.")
        return graph

    def _get_executable_path(self, command_line):
        """
        Robustly extracts the executable path from a full command line string using shlex.
        """
        if not command_line:
            return None
        try:
            parts = shlex.split(command_line)
            if parts:
                return parts[0]
            return None
        except (IndexError, ValueError):
            logging.warning(f"Could not parse command line with shlex: '{command_line}'. Falling back to simple split.")
            return command_line.split(' ')[0]

    def _correlate_process_to_software(self, graph):
        """
        Creates Software nodes and links Process nodes to them using the
        pre-discovered 'owning_package' field.
        """
        logging.info("CorrelationEngine: Running Process-to-Software correlation...")
        processes = [(n, d) for n, d in graph.nodes(data=True) if d.get('node_type') == 'Process']
        
        for process_id, process_attrs in processes:
            server_id = process_attrs.get('server_id')
            package_name = process_attrs.get('owning_package')
            
            if not package_name or not server_id:
                continue

            # Find the software package details from our pre-loaded map
            software_info = self.software_map.get((server_id, package_name))
            if software_info:
                software_node_id = f"sw:{server_id}:{package_name}"

                if software_node_id not in graph:
                    graph.add_node(
                        software_node_id,
                        node_type='Software',
                        label=f"{package_name} ({software_info.get('version', 'N/A')})",
                        **software_info
                    )
                
                graph.add_edge(process_id, software_node_id, relationship_type='PART_OF')
        
        logging.info("CorrelationEngine: Process-to-Software correlation complete.")
        return graph

    def _get_mount_point_for_path(self, server_id, file_path):
        """Finds the storage mount that a given file path belongs to."""
        for mount_info in self.storage_mounts.get(server_id, []):
            mount_point = mount_info['mount_point']
            if file_path.startswith(mount_point):
                return mount_info
        return None

    def _correlate_process_to_config_and_storage(self, graph):
        """
        Correlates processes to configuration files and storage mounts.
        """
        logging.info("CorrelationEngine: Running Process-to-Config and Process-to-Storage correlation...")
        processes = [(n, d) for n, d in graph.nodes(data=True) if d.get('node_type') == 'Process']

        for process_id, process_attrs in processes:
            server_id = process_attrs.get('server_id')
            pid = process_attrs.get('pid')
            
            if not server_id or not pid:
                continue

            open_files = self.open_files_map.get(server_id, {}).get(pid, [])
            if not open_files:
                continue

            linked_mounts = set()

            for file_path in open_files:
                if file_path in self.config_files_set.get(server_id, set()):
                    config_node_id = f"cfg:{server_id}:{file_path}"
                    if config_node_id not in graph:
                        graph.add_node(
                            config_node_id,
                            node_type='ConfigurationFile',
                            label=os.path.basename(file_path),
                            path=file_path
                        )
                    graph.add_edge(process_id, config_node_id, relationship_type='USES_CONFIG')

                mount_info = self._get_mount_point_for_path(server_id, file_path)
                if mount_info:
                    mount_point = mount_info['mount_point']
                    if mount_point in linked_mounts:
                        continue
                    
                    storage_node_id = f"mnt:{server_id}:{mount_point}"
                    if storage_node_id not in graph:
                        graph.add_node(
                            storage_node_id,
                            node_type='StorageMount',
                            label=mount_point,
                            **mount_info
                        )
                    graph.add_edge(process_id, storage_node_id, relationship_type='USES_STORAGE')
                    linked_mounts.add(mount_point)

        logging.info("CorrelationEngine: Process-to-Config and Process-to-Storage correlation complete.")
        return graph


class ProfilingAgent:
    """
    Analyzes the collected data to build a dependency graph and identify application clusters.
    """

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.graph = None

    def build_dependency_graph(self):
        """
        Builds a detailed, multi-layered dependency graph (Digital Twin).
        """
        logging.info("ProfilingAgent: Starting Digital Twin graph construction.")
        G = nx.DiGraph()
        servers = self.db_manager.get_all_servers()
        applications = self.db_manager.get_all_applications()
        connections = self.db_manager.get_all_network_connections()
        server_ips = {server['ip_address'] for server in servers}
        server_id_to_ip = {server['id']: server['ip_address'] for server in servers}
        
        logging.info(f"ProfilingAgent: Retrieved {len(servers)} servers, {len(applications)} running applications, and {len(connections)} network connections.")

        logging.info("ProfilingAgent: Building Port-to-PID lookup cache...")
        port_to_pid_map = {}
        for app in applications:
            server_id = app.get('server_id')
            server_ip = server_id_to_ip.get(server_id)
            if not server_ip:
                continue
            
            try:
                listening_ports = json.loads(app.get('listening_ports', '[]'))
                for port in listening_ports:
                    port_to_pid_map[(server_ip, port)] = app['pid']
            except (json.JSONDecodeError, TypeError):
                continue
        logging.info(f"ProfilingAgent: Port-to-PID cache built with {len(port_to_pid_map)} entries.")

        for server in servers:
            server_ip = server['ip_address']
            G.add_node(server_ip, node_type='Server', label=server.get('hostname', server_ip), **server)
        logging.info(f"ProfilingAgent: Created {len(servers)} Server nodes.")

        for app in applications:
            server_id = app.get('server_id')
            server_ip = server_id_to_ip.get(server_id)
            if not server_ip:
                logging.warning(f"ProfilingAgent: Could not find server IP for app with server_id: {server_id}. Skipping.")
                continue
            process_id = f"{server_ip}:{app['pid']}"
            G.add_node(process_id, node_type='Process', label=f"{app['process_name']} ({app['pid']})", **app)
            G.add_edge(process_id, server_ip, relationship_type='RUNS_ON')
        logging.info(f"ProfilingAgent: Created {G.number_of_nodes() - len(servers)} Process nodes and their 'RUNS_ON' relationships.")

        for conn in connections:
            source_server_ip = server_id_to_ip.get(conn['server_id'])
            if not source_server_ip: continue
            source_process_id = f"{source_server_ip}:{conn['source_pid']}"
            if source_process_id not in G:
                continue
            
            dest_ip = conn['destination_ip']
            dest_port = conn['destination_port']
            
            if dest_ip in server_ips:
                dest_pid = port_to_pid_map.get((dest_ip, dest_port))
                if dest_pid:
                    dest_process_id = f"{dest_ip}:{dest_pid}"
                    if dest_process_id in G:
                        logging.debug(f"Resolved internal connection from {source_process_id} to {dest_process_id} on port {dest_port}")
                        G.add_edge(source_process_id, dest_process_id, relationship_type='CONNECTS_TO', port=dest_port)
                    else:
                        logging.warning(f"Connection from {source_process_id} to {dest_ip}:{dest_port} resolved to PID {dest_pid}, but process node {dest_process_id} not in graph. Treating as unresolved.")
                        self._add_external_connection(G, source_process_id, dest_ip, dest_port, is_unresolved=True)
                else:
                    logging.warning(f"Unresolved internal connection from {source_process_id} to {dest_ip}:{dest_port}. No listening process found in cache.")
                    self._add_external_connection(G, source_process_id, dest_ip, dest_port, is_unresolved=True)
            else:
                self._add_external_connection(G, source_process_id, dest_ip, dest_port)
        
        self.graph = G
        logging.info("ProfilingAgent: Digital Twin graph construction complete.")
        return G

    def _add_external_connection(self, G, source_process_id, dest_ip, dest_port, is_unresolved=False):
        """Helper to create or reuse an ExternalService node and connect a process to it."""
        label_prefix = "unresolved" if is_unresolved else "ext"
        endpoint_id = f"{label_prefix}:{dest_ip}:{dest_port}"
        if endpoint_id not in G:
            G.add_node(endpoint_id, node_type='ExternalService', label=endpoint_id, ip_address=dest_ip, port=dest_port, unresolved=is_unresolved)
        G.add_edge(source_process_id, endpoint_id, relationship_type='CONNECTS_TO', port=dest_port)

    def correlate_and_enrich_graph(self):
        """
        Instantiates and runs the CorrelationEngine to enrich the graph.
        """
        if not self.graph:
            logging.error("ProfilingAgent: Graph has not been built yet. Cannot run correlation.")
            return None
        logging.info("ProfilingAgent: Starting graph correlation and enrichment phase.")
        correlation_engine = CorrelationEngine(self.db_manager)
        self.graph = correlation_engine.run_correlation(self.graph)
        logging.info("ProfilingAgent: Graph correlation and enrichment complete.")
        return self.graph

    def find_application_clusters(self):
        """
        Analyzes the dependency graph to find communities of tightly coupled processes.
        """
        if not self.graph:
            logging.error("ProfilingAgent: Graph has not been built yet. Cannot find clusters.")
            return None
        process_graph = self.graph.to_undirected()
        process_nodes = [n for n, d in self.graph.nodes(data=True) if d.get('node_type') == 'Process']
        process_subgraph = process_graph.subgraph(process_nodes)
        logging.info(f"ProfilingAgent: Finding clusters within a subgraph of {len(process_subgraph.nodes())} processes.")
        try:
            communities_generator = community.louvain_communities(process_subgraph, seed=42)
            clusters = [list(c) for c in communities_generator]
            logging.info(f"ProfilingAgent: Discovered {len(clusters)} application clusters.")
            for i, cluster in enumerate(clusters):
                cluster_name = f"Cluster-{i+1}"
                for process_id in cluster:
                    self.graph.nodes[process_id]['cluster'] = cluster_name
            return clusters
        except Exception as e:
            logging.error(f"Could not perform clustering: {e}")
            return None

    def get_external_dependencies(self):
        """
        Identifies all unique external endpoints the application ecosystem connects to.
        """
        if not self.graph:
            logging.error("ProfilingAgent: Graph has not been built yet. Cannot get external dependencies.")
            return None
        
        external_deps = {}
        for node, data in self.graph.nodes(data=True):
            if data.get('node_type') == 'ExternalService':
                external_deps[data['label']] = {} # Initialize with empty details
        
        logging.info(f"ProfilingAgent: Identified {len(external_deps)} unique external dependencies.")
        return external_deps

    def fingerprint_external_services(self, endpoints):
        """
        Uses nmap to actively scan and fingerprint services on external endpoints.
        """
        if not endpoints:
            return {}
        
        try:
            # Check if nmap is installed
            subprocess.run(["nmap", "-V"], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logging.error("Nmap is not installed or not in PATH. Cannot fingerprint services.")
            # Return original endpoints without fingerprinting
            return {ep: {'name': 'nmap not found'} for ep in endpoints}

        updated_endpoints = {}
        for endpoint in endpoints:
            try:
                ip, port = endpoint.split(':')[-2:] # Handles both ext: and unresolved: prefixes
                logging.info(f"Fingerprinting {ip}:{port} with Nmap...")
                
                # Run nmap with service detection and XML output
                result = subprocess.run(
                    ["nmap", "-sV", "-p", port, "--open", "-oX", "-", ip],
                    capture_output=True, text=True, check=True, timeout=60
                )
                
                # Parse the XML output
                root = ET.fromstring(result.stdout)
                service_info = root.find(f".//port[@portid='{port}']/service")
                
                if service_info is not None:
                    updated_endpoints[endpoint] = {
                        'name': service_info.attrib.get('name', 'unknown'),
                        'product': service_info.attrib.get('product', ''),
                        'version': service_info.attrib.get('version', '')
                    }
                else:
                    updated_endpoints[endpoint] = {'name': 'unknown'}

            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ET.ParseError) as e:
                logging.warning(f"Nmap scan failed for {endpoint}: {e}")
                updated_endpoints[endpoint] = {'name': 'scan failed'}
            except Exception as e:
                logging.error(f"An unexpected error occurred during Nmap scan for {endpoint}: {e}")
                updated_endpoints[endpoint] = {'name': 'error'}

        return updated_endpoints

    def get_correlated_details(self, process_id):
        """
        Traverses the graph from a specific process node to find its correlated details.
        """
        if not self.graph or process_id not in self.graph:
            return "N/A", [], []

        software = "N/A"
        configs = []
        storage = []
        
        for successor in self.graph.successors(process_id):
            if successor not in self.graph:
                continue
            
            node_data = self.graph.nodes[successor]
            node_type = node_data.get('node_type')
            
            if node_type == 'Software':
                software = node_data.get('label', 'Unknown Software')
            elif node_type == 'ConfigurationFile':
                configs.append(node_data.get('path', 'Unknown Config'))
            elif node_type == 'StorageMount':
                storage.append(node_data.get('mount_point', 'Unknown Mount'))
                
        return software, configs, storage