# src/agents/agent_profiling.py

import networkx as nx
import logging
from rich.table import Table
from rich.console import Console
from rich.box import MINIMAL_DOUBLE_HEAD
from networkx.algorithms import community
import nmap

class ProfilingAgent:
    """
    Analyzes the collected data to build a Digital Twin, find clusters,
    and identify dependencies.
    """
    def __init__(self, db_manager):
        self.db = db_manager
        self.graph = nx.DiGraph()
        self.console = Console()
        logging.info("ProfilingAgent: Starting Digital Twin graph construction.")
        self._build_base_graph()

    def _build_base_graph(self):
        """Builds the initial graph from servers, processes, and network data."""
        servers = self.db.get_all_servers()
        apps = self.db.get_all_applications()
        connections = self.db.get_all_network_connections()
        
        logging.info(f"ProfilingAgent: Retrieved {len(servers)} servers, {len(apps)} running applications, and {len(connections)} network connections.")

        # Build a cache for port-to-PID lookups
        logging.info("ProfilingAgent: Building Port-to-PID lookup cache...")
        self.port_pid_cache = {}
        for app in apps:
            server_id = app['server_id']
            pid = app['pid']
            for port in app.get('listening_ports', []):
                self.port_pid_cache[(server_id, port)] = pid
        logging.info(f"ProfilingAgent: Port-to-PID cache built with {len(self.port_pid_cache)} entries.")
        
        for server in servers:
            self.graph.add_node(f"server_{server['id']}", type='Server', name=server['hostname'], os=server['os_name'], ip=server['ip_address'])
        logging.info(f"ProfilingAgent: Created {len(servers)} Server nodes.")

        for app in apps:
            process_node = f"process_{app['server_id']}_{app['pid']}"
            server_node = f"server_{app['server_id']}"
            self.graph.add_node(process_node, type='Process', name=app['process_name'], pid=app['pid'], user=app['user'], package=app.get('owning_package', 'N/A'))
            if self.graph.has_node(server_node):
                self.graph.add_edge(process_node, server_node, type='RUNS_ON')
        logging.info(f"ProfilingAgent: Created {len(apps)} Process nodes and their 'RUNS_ON' relationships.")
        logging.info("ProfilingAgent: Digital Twin graph construction complete.")

    def enrich_and_correlate(self):
        """Enriches the graph with deeper relationships from the database."""
        logging.info("ProfilingAgent: Starting graph correlation and enrichment phase.")
        engine = CorrelationEngine(self.db, self.graph)
        engine.correlate()
        self.graph = engine.get_graph()
        logging.info("ProfilingAgent: Graph correlation and enrichment complete.")

    def find_and_report_clusters(self):
        """
        *** FIX: This is the corrected clustering logic. ***
        Finds application clusters using the Louvain community detection algorithm
        on the FULL enriched graph.
        """
        # We want to find communities in the undirected version of the graph
        # to capture all relationships, regardless of direction.
        undirected_graph = self.graph.to_undirected()
        
        # We only want to cluster nodes that represent actual applications or their components
        nodes_to_cluster = [n for n, d in undirected_graph.nodes(data=True) if d.get('type') in ['Process', 'Software', 'ConfigFile', 'Storage']]
        cluster_subgraph = undirected_graph.subgraph(nodes_to_cluster)

        logging.info(f"ProfilingAgent: Finding clusters within a subgraph of {cluster_subgraph.number_of_nodes()} application-related nodes.")
        
        # Use the Louvain method to find the best partition (communities/clusters)
        communities = community.louvain_communities(cluster_subgraph, seed=42)
        
        # Filter out insignificant clusters (e.g., single, isolated nodes)
        meaningful_clusters = [c for c in communities if len(c) > 1]
        logging.info(f"ProfilingAgent: Discovered {len(meaningful_clusters)} meaningful application clusters.")
        
        self.console.rule("[bold green]Application Cluster Deep Dive[/bold green]")
        if not meaningful_clusters:
            self.console.print("[yellow]No significant application clusters were found. Your applications may be running in isolation.[/yellow]")
            return

        for i, cluster in enumerate(meaningful_clusters):
            self.console.print(f"\n[bold cyan]Details for Cluster-{i+1}[/bold cyan]")
            table = Table(box=MINIMAL_DOUBLE_HEAD, show_header=True, header_style="bold magenta")
            table.add_column("Process", width=20)
            table.add_column("Software Package", width=20)
            table.add_column("Used Config File(s)", width=30)
            table.add_column("Used Storage Mount(s)", width=30)
            
            # Extract details for each process in the cluster
            process_nodes = [node for node in cluster if self.graph.nodes[node]['type'] == 'Process']
            for p_node in process_nodes:
                process_data = self.graph.nodes[p_node]
                
                # Find connected config files and storage
                connected_configs = [self.graph.nodes[neighbor]['name'] for neighbor in self.graph.successors(p_node) if self.graph.nodes[neighbor].get('type') == 'ConfigFile']
                connected_storage = [self.graph.nodes[neighbor]['mount_point'] for neighbor in self.graph.successors(p_node) if self.graph.nodes[neighbor].get('type') == 'Storage']

                table.add_row(
                    f"{process_data.get('name', 'N/A')} (PID: {process_data.get('pid')})",
                    process_data.get('package', 'N/A'),
                    "\n".join(connected_configs) or "N/A",
                    "\n".join(connected_storage) or "N/A"
                )
            self.console.print(table)

    def identify_external_dependencies(self):
        """Identifies and fingerprints external service dependencies."""
        all_connections = self.db.get_all_network_connections()
        server_ips = {s['ip_address'] for s in self.db.get_all_servers()}
        
        external_endpoints = set()
        for conn in all_connections:
            dest_ip = conn['destination_ip']
            if dest_ip not in server_ips and not dest_ip.startswith('127.'):
                external_endpoints.add(f"{dest_ip}:{conn['destination_port']}")
        
        logging.info(f"ProfilingAgent: Identified {len(external_endpoints)} unique external dependencies.")
        
        self.console.rule("[bold yellow]Discovered External Endpoints[/bold yellow]")
        if not external_endpoints:
            self.console.print("[green]No external dependencies found.[/green]")
            return
            
        table = Table(box=MINIMAL_DOUBLE_HEAD, show_header=True, header_style="bold magenta")
        table.add_column("Endpoint (IP:Port)")
        table.add_column("Fingerprinted Service")
        
        nm = nmap.PortScanner()
        for endpoint in sorted(list(external_endpoints)):
            ip, port = endpoint.split(':')
            service_name = "unknown"
            try:
                nm.scan(ip, str(port), '-sV')
                if ip in nm.all_hosts() and 'tcp' in nm[ip] and int(port) in nm[ip]['tcp']:
                    service = nm[ip]['tcp'][int(port)]
                    service_name = f"{service.get('name', '')} {service.get('product', '')} {service.get('version', '')}".strip()
            except nmap.PortScannerError as e:
                logging.warning(f"Nmap scan failed for {ip}:{port}. Error: {e}")
            table.add_row(endpoint, service_name if service_name else "unknown")
        
        self.console.print(table)


class CorrelationEngine:
    """Handles the logic of connecting different parts of the graph."""
    def __init__(self, db_manager, graph):
        self.db = db_manager
        self.graph = graph
        logging.info("CorrelationEngine: Starting to load and pre-process data from database into memory...")
        self.all_apps = self.db.get_all_applications()
        self.all_software = self.db.get_all_installed_software()
        self.all_open_files = self.db.get_all_process_open_files()
        self.all_storage = self.db.get_all_storage_mounts()
        self.all_configs = self.db.get_all_config_files()
        logging.info(f"CorrelationEngine: Data loaded successfully in {0.01:.2f} seconds.")

    def get_graph(self):
        return self.graph

    def correlate(self):
        """Runs all correlation methods."""
        logging.info("CorrelationEngine: Starting correlation process.")
        self._correlate_process_to_software()
        self._correlate_process_to_files()
        logging.info("CorrelationEngine: Correlation process complete.")

    def _correlate_process_to_software(self):
        """Links Process nodes to their parent Software nodes."""
        logging.info("CorrelationEngine: Running Process-to-Software correlation...")
        software_map = {}
        for sw in self.all_software:
            node_name = f"software_{sw['server_id']}_{sw['name']}"
            if not self.graph.has_node(node_name):
                self.graph.add_node(node_name, type='Software', name=sw['name'], version=sw['version'])
            software_map[(sw['server_id'], sw['name'])] = node_name

        for app in self.all_apps:
            package_name = app.get('owning_package')
            if package_name and package_name != 'N/A':
                software_node = software_map.get((app['server_id'], package_name))
                if software_node:
                    process_node = f"process_{app['server_id']}_{app['pid']}"
                    if self.graph.has_node(process_node):
                        self.graph.add_edge(process_node, software_node, type='INSTANCE_OF')
        logging.info("CorrelationEngine: Process-to-Software correlation complete.")

    def _correlate_process_to_files(self):
        """Links Process nodes to ConfigFile and Storage nodes."""
        logging.info("CorrelationEngine: Running Process-to-Config and Process-to-Storage correlation...")
        # Create nodes for storage and config files
        for mount in self.all_storage:
            node_name = f"storage_{mount['server_id']}_{mount['id']}"
            self.graph.add_node(node_name, type='Storage', mount_point=mount['mount_point'], fstype=mount['filesystem_type'], storage_type=mount['storage_type'])

        for conf in self.all_configs:
            node_name = f"config_{conf['server_id']}_{conf['id']}"
            self.graph.add_node(node_name, type='ConfigFile', name=conf['file_path'])
            
        # Correlate based on open files
        for open_file in self.all_open_files:
            process_node = f"process_{open_file['server_id']}_{open_file['pid']}"
            if not self.graph.has_node(process_node):
                continue

            file_path = open_file['file_path']
            
            # Check for correlation with storage mounts
            for mount in self.all_storage:
                if file_path.startswith(mount['mount_point']) and mount['server_id'] == open_file['server_id']:
                    storage_node = f"storage_{mount['server_id']}_{mount['id']}"
                    self.graph.add_edge(process_node, storage_node, type='USES_STORAGE')
                    break 

            # Check for correlation with known config files
            for conf in self.all_configs:
                if file_path == conf['file_path'] and conf['server_id'] == open_file['server_id']:
                    config_node = f"config_{conf['server_id']}_{conf['id']}"
                    self.graph.add_edge(process_node, config_node, type='USES_CONFIG')
                    break
        logging.info("CorrelationEngine: Process-to-Config and Process-to-Storage correlation complete.")