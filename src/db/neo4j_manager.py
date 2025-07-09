# src/db/neo4j_manager.py

import logging
import yaml
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

class Neo4jManager:
    """
    Manages all interactions with the Neo4j database, including exporting
    the NetworkX graph to Neo4j.
    """

    def __init__(self, uri, user, password):
        """
        Initializes the Neo4jManager and establishes a connection.
        """
        self.driver = None
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            logging.info("Successfully connected to Neo4j database.")
        except Exception as e:
            logging.error(f"Failed to connect to Neo4j: {e}")
            raise

    def close(self):
        """Closes the Neo4j database connection."""
        if self.driver:
            self.driver.close()
            logging.info("Neo4j connection closed.")

    def _run_write_query(self, query, params=None):
        """Helper to run a write transaction."""
        with self.driver.session() as session:
            session.write_transaction(lambda tx: tx.run(query, params))

    def clear_database(self):
        """Deletes all nodes and relationships from the database."""
        logging.info("Clearing existing data from Neo4j database...")
        query = "MATCH (n) DETACH DELETE n"
        self._run_write_query(query)
        logging.info("Database cleared.")

    def create_constraints(self):
        """Creates unique constraints for each node type to prevent duplicates."""
        logging.info("Creating unique constraints for node labels...")
        constraints = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Server) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Process) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Software) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Storage) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ConfigFile) REQUIRE n.unique_id IS UNIQUE"
        ]
        for constraint in constraints:
            try:
                self._run_write_query(constraint)
            except Exception as e:
                logging.warning(f"Could not create constraint (it may already exist): {e}")
        logging.info("Constraints created successfully.")

    def export_graph(self, graph):
        """Exports the entire NetworkX graph to Neo4j."""
        self.clear_database()
        self.create_constraints()

        # Export nodes
        logging.info("Starting node export to Neo4j...")
        # *** FIX: Using standard Cypher instead of APOC procedures ***
        node_query = """
        UNWIND $nodes as node_data
        // Create the node with its primary type
        CREATE (n)
        // Set all properties from the dictionary
        SET n = node_data.properties
        // Dynamically set all labels from the list
        WITH n, node_data.labels as labels
        CALL apoc.create.addLabels(n, labels) YIELD node
        RETURN count(node)
        """
        
        # *** REPLACEMENT FIX: This is the new, standard Cypher approach ***
        node_query_standard = """
        UNWIND $nodes as node_data
        // Create the node with a placeholder label
        CREATE (n:Node)
        // Set all properties from the dictionary
        SET n = node_data.properties
        // Remove the placeholder and add the correct labels
        REMOVE n:Node
        WITH n, node_data.labels as labels
        FOREACH (label IN labels | SET n:label)
        """
        
        nodes_to_export = []
        for node, data in graph.nodes(data=True):
            properties = data.copy()
            # Ensure a unique ID for constraint
            properties['unique_id'] = node 
            # Get all labels for the node, starting with its primary 'type'
            labels = [properties.get('type', 'Unknown')]
            nodes_to_export.append({'labels': labels, 'properties': properties})

        if nodes_to_export:
            self._run_write_query(node_query_standard, params={'nodes': nodes_to_export})
        logging.info(f"Exported {len(nodes_to_export)} nodes.")

        # Export relationships
        logging.info("Starting relationship export to Neo4j...")
        relationship_query = """
        UNWIND $rels as rel
        MATCH (a {unique_id: rel.source})
        MATCH (b {unique_id: rel.target})
        CALL apoc.create.relationship(a, rel.type, rel.properties, b) YIELD rel
        RETURN count(rel)
        """
        
        # *** REPLACEMENT FIX: This is the new, standard Cypher approach ***
        relationship_query_standard = """
        UNWIND $rels as rel_data
        MATCH (a {unique_id: rel_data.source})
        MATCH (b {unique_id: rel_data.target})
        // Use a CASE statement to dynamically create the relationship type
        CALL {
            WITH a, b, rel_data
            CALL apoc.cypher.doIt('CREATE (a)-[r:' + rel_data.type + ']->(b) SET r = $props RETURN r', {a:a, b:b, props:rel_data.properties}) YIELD value
            RETURN value
        }
        RETURN count(value)
        """
        
        # Final, simplest, and best approach without any special procedures
        relationship_query_final = """
        UNWIND $rels as rel_data
        MATCH (a {unique_id: rel_data.source})
        MATCH (b {unique_id: rel_data.target})
        CREATE (a)-[r:RELATIONSHIP]->(b)
        SET r = rel_data.properties, r.type = rel_data.type
        """


        rels_to_export = []
        for source, target, data in graph.edges(data=True):
            properties = data.copy()
            rel_type = properties.pop('type', 'RELATED_TO').upper()
            rels_to_export.append({
                'source': source,
                'target': target,
                'type': rel_type,
                'properties': properties
            })
        
        if rels_to_export:
             # We need to run this in batches for each relationship type
            rel_types = set(r['type'] for r in rels_to_export)
            for rel_type in rel_types:
                batch = [r for r in rels_to_export if r['type'] == rel_type]
                # Build a dynamic query for each relationship type
                batch_query = f"""
                UNWIND $rels as rel_data
                MATCH (a {{unique_id: rel_data.source}})
                MATCH (b {{unique_id: rel_data.target}})
                CREATE (a)-[r:`{rel_type}`]->(b)
                SET r = rel_data.properties
                """
                self._run_write_query(batch_query, params={'rels': batch})

        logging.info(f"Exported {len(rels_to_export)} relationships.")