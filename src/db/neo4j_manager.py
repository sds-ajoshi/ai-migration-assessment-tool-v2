# src/db/neo4j_manager.py

import os
import logging
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

class Neo4jManager:
    """
    Manages all interactions with the Neo4j database, including exporting the graph.
    """

    def __init__(self, uri, user, password):
        """
        Initializes the Neo4jManager and connects to the database.

        Args:
            uri (str): The URI for the Neo4j database (e.g., "bolt://localhost:7687").
            user (str): The username for the database.
            password (str): The password for the database.
        """
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            logging.info("Successfully connected to Neo4j database.")
        except Exception as e:
            logging.error(f"Failed to connect to Neo4j. Please check credentials and connection settings. Error: {e}")
            self.driver = None

    def close(self):
        """Closes the database connection."""
        if self.driver:
            self.driver.close()
            logging.info("Neo4j connection closed.")

    def _sanitize_properties(self, properties):
        """
        Sanitizes node/relationship properties to be compatible with Neo4j.
        - Allows lists of primitive types to pass through for native array storage.
        - Converts dictionaries and other complex types to strings.
        """
        sanitized = {}
        if not properties:
            return sanitized
        for key, value in properties.items():
            if value is None:
                continue
            
            if isinstance(value, list):
                # Check if all items in the list are primitive types that Neo4j supports in arrays
                is_primitive_list = all(isinstance(item, (int, float, str, bool, type(None))) for item in value)
                if is_primitive_list:
                    sanitized[key] = value # Pass through as native array
                else:
                    # Convert list of complex types (e.g., list of dicts) to a string
                    sanitized[key] = str(value)
            elif isinstance(value, dict):
                # Always convert dictionaries to a string representation
                sanitized[key] = str(value)
            elif isinstance(value, (int, float, str, bool)):
                # Standard primitive types are supported directly
                sanitized[key] = value
            else:
                # Fallback for any other unexpected types
                sanitized[key] = str(value)
        return sanitized

    def export_graph_to_neo4j(self, G):
        """
        Exports the entire NetworkX graph (G) to the Neo4j database.
        This function handles the new Digital Twin model with multiple node and relationship types.

        Args:
            G (networkx.DiGraph): The graph to export.
        """
        if not self.driver:
            logging.error("No active Neo4j driver. Cannot export graph.")
            return

        with self.driver.session() as session:
            logging.info("Clearing existing data from Neo4j database...")
            session.run("MATCH (n) DETACH DELETE n")
            logging.info("Database cleared.")

            logging.info("Creating unique constraints for node labels...")
            # Use a consistent primary key 'id' across all nodes for simplicity
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Server) REQUIRE n.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Process) REQUIRE n.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:ExternalService) REQUIRE n.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Software) REQUIRE n.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:ConfigurationFile) REQUIRE n.id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:StorageMount) REQUIRE n.id IS UNIQUE")
            logging.info("Constraints created successfully.")

            logging.info("Starting node export to Neo4j...")
            nodes = list(G.nodes(data=True))
            batch_size = 500
            for i in range(0, len(nodes), batch_size):
                batch = nodes[i:i + batch_size]
                node_data = []
                for node_id, attrs in batch:
                    properties = self._sanitize_properties(attrs)
                    properties['id'] = node_id # Ensure the primary key is in the properties
                    
                    node_data.append({
                        'id': node_id,
                        'labels': [attrs.get('node_type', 'Unknown')],
                        'properties': properties
                    })
                
                # Using apoc.create.node for dynamic labels
                session.run("""
                    UNWIND $nodes as node_info
                    MERGE (n {id: node_info.id})
                    SET n = node_info.properties
                    WITH n, node_info.labels as labels
                    CALL apoc.create.addLabels(n, labels) YIELD node
                    RETURN count(node)
                """, nodes=node_data)
                logging.info(f"Exported batch of {len(batch)} nodes.")
            logging.info(f"Finished exporting {len(nodes)} nodes.")

            logging.info("Starting relationship export to Neo4j...")
            edges = list(G.edges(data=True))
            for i in range(0, len(edges), batch_size):
                batch = edges[i:i + batch_size]
                edge_data = []
                for source_id, dest_id, attrs in batch:
                    rel_type = attrs.get('relationship_type', 'RELATED_TO').upper()
                    properties = self._sanitize_properties(attrs)
                    edge_data.append({
                        'source': source_id,
                        'target': dest_id,
                        'type': rel_type,
                        'properties': properties
                    })

                session.run("""
                    UNWIND $rels as rel
                    MATCH (a {id: rel.source})
                    MATCH (b {id: rel.target})
                    CALL apoc.create.relationship(a, rel.type, rel.properties, b) YIELD rel as result
                    RETURN count(result)
                """, rels=edge_data)
                logging.info(f"Exported batch of {len(batch)} relationships.")
            logging.info(f"Finished exporting {len(edges)} relationships.")
            logging.info("Graph export to Neo4j completed successfully.")

def get_neo4j_manager_from_env():
    """
    Creates a Neo4jManager instance from environment variables.
    """
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD")

    if not password:
        logging.error("NEO4J_PASSWORD environment variable not set. Cannot connect to Neo4j.")
        return None
    
    return Neo4jManager(uri, user, password)