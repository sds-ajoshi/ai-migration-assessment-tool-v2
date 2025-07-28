# src/db/neo4j_manager.py

import logging
import time
from typing import List, Tuple, Dict, Optional
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, TransientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s'
)

class Neo4jManager:
    """
    Manages interactions with Neo4j database, providing robust Cypher execution,
    batch processing, and index management for the Digital Twin pipeline.
    """

    def __init__(self, uri: str, user: str, password: str, max_retries: int = 3, retry_delay: float = 1.0):
        """
        Initialize Neo4jManager with connection parameters and retry configuration.
        
        Args:
            uri: Neo4j connection URI (e.g., 'neo4j://localhost:7687')
            user: Neo4j username
            password: Neo4j password
            max_retries: Maximum number of retries for failed connections/queries
            retry_delay: Initial delay (seconds) for exponential backoff
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.driver = None
        self._connect()

    def _connect(self):
        """Establish connection to Neo4j with retry logic."""
        attempt = 0
        while attempt < self.max_retries:
            try:
                self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
                self.driver.verify_connectivity()
                logging.info("Successfully connected to Neo4j database.")
                return
            except ServiceUnavailable as e:
                attempt += 1
                if attempt == self.max_retries:
                    logging.error(f"Failed to connect to Neo4j after {self.max_retries} attempts: {e}")
                    raise
                wait_time = self.retry_delay * (2 ** (attempt - 1))
                logging.warning(f"Connection attempt {attempt} failed, retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
        raise Exception("Failed to initialize Neo4j connection")

    def close(self):
        """Close the Neo4j driver connection."""
        if self.driver:
            self.driver.close()
            logging.info("Neo4j connection closed.")
            self.driver = None

    def ping(self) -> bool:
        """Check if the Neo4j connection is alive."""
        try:
            with self.driver.session() as session:
                session.run("RETURN 1").consume()
            logging.debug("Neo4j connection ping successful.")
            return True
        except Exception as e:
            logging.error(f"Neo4j connection ping failed: {e}")
            return False

    def run_cypher(self, query: str, params: Optional[Dict] = None, dry_run: bool = False) -> None:
        """
        Execute a single Cypher query with optional parameters and retry logic.
        
        Args:
            query: Cypher query string
            params: Dictionary of query parameters
            dry_run: If True, log the query instead of executing it
        """
        if dry_run:
            logging.info(f"Dry run - Query: {query}, Params: {params or {}}")
            return

        attempt = 0
        params = params or {}
        while attempt < self.max_retries:
            try:
                with self.driver.session() as session:
                    session.write_transaction(lambda tx: tx.run(query, **params))
                logging.debug(f"Executed query: {query}")
                return
            except (ServiceUnavailable, TransientError) as e:
                attempt += 1
                if attempt == self.max_retries:
                    logging.error(f"Failed to execute query after {self.max_retries} attempts: {query}, Error: {e}")
                    raise
                wait_time = self.retry_delay * (2 ** (attempt - 1))
                logging.warning(f"Query attempt {attempt} failed, retrying in {wait_time}s: {e}")
                time.sleep(wait_time)
            except Exception as e:
                logging.error(f"Query execution failed: {query}, Error: {e}")
                raise

    def run_batch(self, queries: List[Tuple[str, Dict]], batch_size: int = 1000, dry_run: bool = False) -> None:
        """
        Execute a batch of Cypher queries in chunks to optimize performance.
        
        Args:
            queries: List of tuples containing (query, params)
            batch_size: Number of queries to process per transaction
            dry_run: If True, log queries instead of executing
        """
        if dry_run:
            for query, params in queries:
                logging.info(f"Dry run - Batch query: {query}, Params: {params or {}}")
            logging.info(f"Dry run - Total queries: {len(queries)}")
            return

        for i in range(0, len(queries), batch_size):
            batch = queries[i:i + batch_size]
            attempt = 0
            while attempt < self.max_retries:
                try:
                    with self.driver.session() as session:
                        for query, params in batch:
                            session.write_transaction(lambda tx: tx.run(query, **(params or {})))
                    logging.debug(f"Executed batch {i//batch_size + 1} with {len(batch)} queries")
                    break
                except (ServiceUnavailable, TransientError) as e:
                    attempt += 1
                    if attempt == self.max_retries:
                        logging.error(f"Failed to execute batch {i//batch_size + 1} after {self.max_retries} attempts: {e}")
                        raise
                    wait_time = self.retry_delay * (2 ** (attempt - 1))
                    logging.warning(f"Batch {i//batch_size + 1} attempt {attempt} failed, retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                except Exception as e:
                    logging.error(f"Batch {i//batch_size + 1} execution failed: {e}")
                    raise
        logging.info(f"Completed batch processing of {len(queries)} queries")

    def create_indexes(self, dry_run: bool = False) -> None:
        """
        Create indexes for common node types to optimize query performance.
        """
        logging.info("Creating indexes for node types...")
        index_queries = [
            ("CREATE INDEX IF NOT EXISTS FOR (n:Server) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:Process) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:StorageMount) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:InstalledSoftware) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:Service) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:Port) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:NetworkInterface) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:DNSServer) ON (n.node_id)", {}),
            ("CREATE INDEX IF NOT EXISTS FOR (n:ExternalService) ON (n.node_id)", {})
        ]
        self.run_batch(index_queries, batch_size=1, dry_run=dry_run)
        logging.info("Indexes created successfully.")

    def clear_database(self, dry_run: bool = False) -> None:
        """Delete all nodes and relationships from the database."""
        logging.info("Clearing existing data from Neo4j database...")
        query = "MATCH (n) DETACH DELETE n"
        self.run_cypher(query, dry_run=dry_run)
        logging.info("Database cleared.")

    def create_constraints(self, dry_run: bool = False) -> None:
        """Create unique constraints for each node type to prevent duplicates."""
        logging.info("Creating unique constraints for node labels...")
        constraint_queries = [
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Server) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Process) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:StorageMount) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:InstalledSoftware) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Service) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Port) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:NetworkInterface) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:DNSServer) REQUIRE n.node_id IS UNIQUE", {}),
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:ExternalService) REQUIRE n.node_id IS UNIQUE", {})
        ]
        self.run_batch(constraint_queries, batch_size=1, dry_run=dry_run)
        logging.info("Constraints created successfully.")

    def export_graph(self, graph, dry_run: bool = False):
        """
        Export a networkx graph object to Neo4j using standard Cypher.
        
        Args:
            graph: NetworkX graph object
            dry_run: If True, log queries instead of executing
        """
        self.clear_database(dry_run=dry_run)
        self.create_constraints(dry_run=dry_run)
        self.create_indexes(dry_run=dry_run)

        # Export Nodes
        logging.info("Exporting nodes to Neo4j...")
        node_queries = []
        for node_id, data in graph.nodes(data=True):
            props = data.copy()
            props['node_id'] = str(node_id)
            if 'name' not in props:
                props['name'] = str(node_id)
            label = props.get('type', 'Node').replace('_', '')
            query = f"MERGE (n:{label} {{node_id: $node_id}}) SET n += $props"
            node_queries.append((query, {'node_id': str(node_id), 'props': props}))
        
        self.run_batch(node_queries, batch_size=1000, dry_run=dry_run)
        logging.info(f"Exported {len(node_queries)} nodes.")

        # Export Relationships
        logging.info("Exporting relationships to Neo4j...")
        rel_queries = []
        for source, target, data in graph.edges(data=True):
            props = data.copy()
            rel_type = props.pop('type', 'RELATED_TO').upper()
            query = f"""
            MATCH (a {{node_id: $source}})
            MATCH (b {{node_id: $target}})
            MERGE (a)-[r:{rel_type}]->(b)
            SET r += $props
            """
            rel_queries.append((query, {'source': str(source), 'target': str(target), 'props': props}))

        self.run_batch(rel_queries, batch_size=1000, dry_run=dry_run)
        logging.info(f"Exported {len(rel_queries)} relationships.")