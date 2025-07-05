import networkx as nx
import sqlite3
import os
import community as community_louvain
from collections import defaultdict
from neo4j import Driver, unit_of_work

# Add the src directory to the Python path to allow for imports
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db import neo4j_manager # Import the new manager

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
    """Builds a dependency graph from the data stored in the SQLite database."""
    print("[*] Building dependency graph...")
    servers, connections = get_data_from_db(db_connection)
    G = nx.DiGraph()
    for server_ip in servers:
        G.add_node(server_ip)
    print(f"  [*] Added {len(servers)} servers as nodes.")
    edge_count = 0
    for source_ip, dest_ip, dest_port in connections:
        if dest_ip in servers:
            G.add_edge(source_ip, dest_ip, port=dest_port)
            edge_count += 1
    print(f"  [*] Created {edge_count} edges representing internal connections.")
    print("[*] Dependency graph built successfully.")
    return G

def find_application_clusters(graph):
    """Analyzes the dependency graph to find application clusters."""
    print("\n[*] Finding application clusters...")
    if graph.number_of_nodes() == 0:
        print("  [*] Graph is empty, no clusters to find.")
        return {}
    undirected_graph = graph.to_undirected()
    partition = community_louvain.best_partition(undirected_graph)
    clusters = defaultdict(list)
    for node, community_id in partition.items():
        clusters[community_id].append(node)
    print(f"  [*] Identified {len(clusters)} potential application clusters.")
    return dict(clusters)

# --- REFACTORED BATCH EXPORT FUNCTIONS ---

@unit_of_work(timeout=30)
def batch_create_nodes(tx, nodes_data):
    """
    Creates all server nodes in a single, efficient transaction using UNWIND.
    """
    query = """
    UNWIND $nodes AS node_data
    MERGE (s:Server {ip_address: node_data.ip})
    """
    tx.run(query, nodes=nodes_data)

@unit_of_work(timeout=30)
def batch_create_relationships(tx, edges_data):
    """
    Creates all relationships in a single, efficient transaction using UNWIND.
    """
    query = """
    UNWIND $edges AS edge_data
    MATCH (a:Server {ip_address: edge_data.source})
    MATCH (b:Server {ip_address: edge_data.dest})
    MERGE (a)-[r:CONNECTS_TO {port: edge_data.port}]->(b)
    """
    tx.run(query, edges=edges_data)

def export_graph_to_neo4j(graph: nx.DiGraph, driver: Driver):
    """
    Exports the NetworkX graph to a Neo4j database using efficient, idempotent
    batch queries. This is the refined implementation.
    """
    print("\n[*] Exporting dependency graph to Neo4j using batch operations...")
    
    with driver.session(database="neo4j") as session:
        # Create constraints for uniqueness (best practice)
        try:
            session.run("CREATE CONSTRAINT server_ip IF NOT EXISTS FOR (s:Server) REQUIRE s.ip_address IS UNIQUE")
        except Exception as e:
            print(f"  [!] Note: Could not create constraint, may already exist or lack permissions. Error: {e}")

        # 1. Prepare node data for batching
        nodes_to_create = [{"ip": node} for node in graph.nodes()]
        
        # 2. Prepare edge data for batching
        edges_to_create = [
            {"source": source, "dest": dest, "port": data.get('port')}
            for source, dest, data in graph.edges(data=True)
        ]

        # 3. Execute batch operations
        if nodes_to_create:
            session.execute_write(batch_create_nodes, nodes_to_create)
            print(f"  [*] Merged {len(nodes_to_create)} server nodes into Neo4j.")
        
        if edges_to_create:
            session.execute_write(batch_create_relationships, edges_to_create)
            print(f"  [*] Merged {len(edges_to_create)} relationships into Neo4j.")
    
    print("[*] Graph export to Neo4j complete.")


# Example usage for standalone testing of this module
if __name__ == '__main__':
    TEST_DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'assessment_history.db')
    
    if not os.path.exists(TEST_DB_FILE):
        print(f"Error: Database file not found at {TEST_DB_FILE}.")
    else:
        conn = sqlite3.connect(TEST_DB_FILE)
        dependency_graph = build_dependency_graph(conn)
        conn.close()
        
        neo4j_driver = neo4j_manager.get_neo4j_driver()
        if neo4j_driver and dependency_graph.number_of_nodes() > 0:
            export_graph_to_neo4j(dependency_graph, neo4j_driver)
            neo4j_manager.close_driver(neo4j_driver)
        elif not neo4j_driver:
            print("\nCould not test Neo4j export: failed to get driver. Is it running and are environment variables set?")
        else:
            print("\nCould not test Neo4j export: graph is empty.")