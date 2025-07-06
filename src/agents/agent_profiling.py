import networkx as nx
import sqlite3
import os
import community as community_louvain
from collections import defaultdict
from neo4j import Driver

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db import neo4j_manager

def get_data_from_db(conn):
    """Fetches server and network connection data from the database."""
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM servers")
    servers = {row[0] for row in cursor.fetchall()}
    cursor.execute("""
        SELECT s.ip_address, nc.destination_ip, nc.destination_port
        FROM network_connections nc
        JOIN servers s ON nc.source_server_id = s.id
    """)
    connections = cursor.fetchall()
    return servers, connections

def build_dependency_graph(db_connection):
    """Builds a dependency graph, including nodes for external services."""
    print("[*] Building dependency graph (including external endpoints)...")
    servers, connections = get_data_from_db(db_connection)
    G = nx.DiGraph()
    for server_ip in servers:
        G.add_node(server_ip, type='server')
    print(f"  [*] Added {len(servers)} internal servers as nodes.")
    external_nodes = set()
    edge_count = 0
    for source_ip, dest_ip, dest_port in connections:
        if dest_ip not in servers:
            if dest_ip not in G:
                G.add_node(dest_ip, type='external')
                external_nodes.add(dest_ip)
        G.add_edge(source_ip, dest_ip, port=dest_port)
        edge_count += 1
    print(f"  [*] Added {len(external_nodes)} external service nodes.")
    print(f"  [*] Created {edge_count} total edges.")
    print("[*] Dependency graph built successfully.")
    return G

def find_application_clusters(graph):
    """Analyzes the dependency graph to find application clusters."""
    print("\n[*] Finding application clusters...")
    if graph.number_of_nodes() == 0:
        return {}
    server_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'server']
    server_subgraph = graph.subgraph(server_nodes)
    undirected_graph = server_subgraph.to_undirected()
    if undirected_graph.number_of_edges() == 0:
        print("  [*] No internal connections found to form clusters.")
        return {i: [node] for i, node in enumerate(server_nodes)}
    partition = community_louvain.best_partition(undirected_graph)
    clusters = defaultdict(list)
    for node, community_id in partition.items():
        clusters[community_id].append(node)
    print(f"  [*] Identified {len(clusters)} potential application clusters.")
    return dict(clusters)

def get_external_endpoints(graph: nx.DiGraph):
    """Identifies all external endpoints our internal servers are connecting to."""
    print("\n[*] Identifying external endpoints...")
    external_endpoints = defaultdict(lambda: defaultdict(list))
    for source, dest, data in graph.edges(data=True):
        source_node = graph.nodes[source]
        dest_node = graph.nodes[dest]
        if source_node.get('type') == 'server' and dest_node.get('type') == 'external':
            port = data.get('port')
            endpoint_key = f"{dest}:{port}"
            if source not in external_endpoints[endpoint_key]['connected_servers']:
                external_endpoints[endpoint_key]['connected_servers'].append(source)
    print(f"  [*] Found {len(external_endpoints)} unique external endpoints.")
    return external_endpoints

def export_graph_to_neo4j(graph: nx.DiGraph, driver: Driver):
    """Exports the NetworkX graph to Neo4j, handling different node labels."""
    print("\n[*] Exporting dependency graph to Neo4j using batch operations...")
    with driver.session(database="neo4j") as session:
        try:
            session.run("CREATE CONSTRAINT server_ip IF NOT EXISTS FOR (s:Server) REQUIRE s.ip_address IS UNIQUE")
            session.run("CREATE CONSTRAINT external_ip IF NOT EXISTS FOR (e:ExternalService) REQUIRE e.ip_address IS UNIQUE")
        except Exception as e:
            print(f"  [!] Note: Could not create constraints. Error: {e}")

        server_nodes = [{"ip": n} for n, d in graph.nodes(data=True) if d.get('type') == 'server']
        external_nodes = [{"ip": n} for n, d in graph.nodes(data=True) if d.get('type') == 'external']
        edges_to_create = [{"source": source, "dest": dest, "port": data.get('port')} for source, dest, data in graph.edges(data=True)]

        if server_nodes:
            session.execute_write(lambda tx, data: tx.run("UNWIND $data AS node_data MERGE (s:Server {ip_address: node_data.ip})", data=data))
            print(f"  [*] Merged {len(server_nodes)} Server nodes into Neo4j.")
        if external_nodes:
            session.execute_write(lambda tx, data: tx.run("UNWIND $data AS node_data MERGE (e:ExternalService {ip_address: node_data.ip})", data=data))
            print(f"  [*] Merged {len(external_nodes)} ExternalService nodes into Neo4j.")
        if edges_to_create:
            session.execute_write(lambda tx, data: tx.run("UNWIND $data AS edge_data MATCH (a:Server {ip_address: edge_data.source}) MATCH (b {ip_address: edge_data.dest}) MERGE (a)-[r:CONNECTS_TO {port: edge_data.port}]->(b)", data=data))
            print(f"  [*] Merged {len(edges_to_create)} relationships into Neo4j.")
    print("[*] Graph export to Neo4j complete.")


def correlate_data(conn):
    """
    Performs data correlation to link running processes (applications) to the
    configuration files they are using. This fulfills Task 3.1 for Sprint 6.
    """
    print("\n[*] Correlating application processes to configuration files...")
    cursor = conn.cursor()

    # 1. Fetch all necessary data
    cursor.execute("SELECT id, file_path, server_id FROM configuration_files")
    configs = cursor.fetchall()
    config_map = {f"{cfg[2]}-{cfg[1]}": cfg[0] for cfg in configs} # key: server_id-filepath -> cfg_id

    cursor.execute("SELECT a.id, a.server_id, pof.file_path FROM process_open_files pof JOIN applications a ON pof.application_id = a.id")
    open_files = cursor.fetchall()

    # Create a mapping table if it doesn't exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS application_config_map (
        application_id INTEGER NOT NULL,
        config_file_id INTEGER NOT NULL,
        PRIMARY KEY (application_id, config_file_id),
        FOREIGN KEY (application_id) REFERENCES applications (id),
        FOREIGN KEY (config_file_id) REFERENCES configuration_files (id)
    );
    """)

    # 2. Find matches and create correlation records
    correlations_to_add = []
    for app_id, server_id, open_file_path in open_files:
        config_key = f"{server_id}-{open_file_path}"
        if config_key in config_map:
            config_file_id = config_map[config_key]
            correlations_to_add.append((app_id, config_file_id))

    # 3. Persist the correlations
    if correlations_to_add:
        # Use set to ensure uniqueness before inserting
        unique_correlations = list(set(correlations_to_add))
        print(f"  [*] Found {len(unique_correlations)} correlations between processes and configs.")
        sql = "INSERT OR IGNORE INTO application_config_map(application_id, config_file_id) VALUES(?,?)"
        cursor.executemany(sql, unique_correlations)
        conn.commit()
    else:
        print("  [*] No direct correlations found between running processes and discovered config files.")