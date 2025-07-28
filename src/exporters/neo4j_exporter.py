# src/exporters/neo4j_exporter.py

import logging
import time
from typing import List, Tuple, Dict, Optional
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, TransientError
import networkx as nx
from networkx.readwrite import json_graph
import json
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True
)

class Neo4jExporter:
    """
    Manages export of graphs to Neo4j with retries, metrics, and structured logging.
    """
    def __init__(self, uri: str, user: str, password: str, max_retries: int = 3, retry_delay: float = 1.0):
        self.uri = uri
        self.user = user
        self.password = password
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.driver = None
        self.logger = structlog.get_logger(__name__)
        self._connect()

    def _connect(self):
        """Establish connection to Neo4j with retry logic."""
        @retry(stop=stop_after_attempt(self.max_retries), wait=wait_exponential(multiplier=self.retry_delay, min=1, max=10))
        def connect_attempt():
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            self.logger.info("Successfully connected to Neo4j database.")

        try:
            connect_attempt()
        except Exception as e:
            self.logger.error("Failed to connect to Neo4j after retries", error=str(e))
            raise

    def close(self):
        if self.driver:
            self.driver.close()
            self.logger.info("Neo4j connection closed.")
            self.driver = None

    def ping(self) -> bool:
        try:
            with self.driver.session() as session:
                session.run("RETURN 1").consume()
            self.logger.debug("Neo4j connection ping successful.")
            return True
        except Exception as e:
            self.logger.error("Neo4j connection ping failed", error=str(e))
            return False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
    def run_cypher(self, query: str, params: Optional[Dict] = None, dry_run: bool = False) -> None:
        start_time = time.time()
        if dry_run:
            self.logger.info("Dry run - Query", query=query, params=params or {})
            return
        params = params or {}
        try:
            with self.driver.session() as session:
                session.execute_write(lambda tx: tx.run(query, **params))
            duration = time.time() - start_time
            self.logger.debug("Executed query", query=query, duration=duration)
        except (ServiceUnavailable, TransientError) as e:
            self.logger.warning("Query attempt failed, retrying", query=query, error=str(e))
            raise
        except Exception as e:
            self.logger.error("Query execution failed", query=query, error=str(e))
            raise

    def run_batch(self, queries: List[Tuple[str, Dict]], batch_size: int = 1000, dry_run: bool = False) -> None:
        start_time = time.time()
        if dry_run:
            for query, params in queries:
                self.logger.info("Dry run - Batch query", query=query, params=params or {})
            self.logger.info("Dry run - Total queries", total_queries=len(queries))
            return

        for i in range(0, len(queries), batch_size):
            batch = queries[i:i + batch_size]
            try:
                with self.driver.session() as session:
                    for query, params in batch:
                        session.execute_write(lambda tx: tx.run(query, **(params or {})))
                self.logger.debug("Executed batch", batch_number=i//batch_size + 1, batch_size=len(batch))
            except Exception as e:
                self.logger.error("Batch execution failed", batch_number=i//batch_size + 1, error=str(e))
                raise
        duration = time.time() - start_time
        self.logger.info("Completed batch processing", total_queries=len(queries), duration=duration)

    def create_indexes(self, dry_run: bool = False) -> None:
        self.logger.info("Creating indexes for node types...")
        index_queries = [
            ("CREATE INDEX IF NOT EXISTS FOR (n:Server) ON (n.node_id)", {}),
            # ... other indexes
        ]
        self.run_batch(index_queries, batch_size=1, dry_run=dry_run)
        self.logger.info("Indexes created successfully.")

    def clear_database(self, dry_run: bool = False) -> None:
        self.logger.info("Clearing existing data from Neo4j database...")
        query = "MATCH (n) DETACH DELETE n"
        self.run_cypher(query, dry_run=dry_run)
        self.logger.info("Database cleared.")

    def create_constraints(self, dry_run: bool = False) -> None:
        self.logger.info("Creating unique constraints for node labels...")
        constraint_queries = [
            ("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Server) REQUIRE n.node_id IS UNIQUE", {}),
            # ... other constraints
        ]
        self.run_batch(constraint_queries, batch_size=1, dry_run=dry_run)
        self.logger.info("Constraints created successfully.")

    def export_graph(self, graph: nx.Graph, dry_run: bool = False) -> Dict[str, float]:
        start_time = time.time()
        metrics = {}
        self.clear_database(dry_run=dry_run)
        metrics['clear_duration'] = time.time() - start_time

        start_time = time.time()
        self.create_constraints(dry_run=dry_run)
        metrics['constraints_duration'] = time.time() - start_time

        start_time = time.time()
        self.create_indexes(dry_run=dry_run)
        metrics['indexes_duration'] = time.time() - start_time

        self.logger.info("Exporting nodes to Neo4j...")
        node_queries = []
        for node_id, data in graph.nodes(data=True):
            props = data.copy()
            props['node_id'] = str(node_id)
            if 'name' not in props:
                props['name'] = str(node_id)
            label = props.get('type', 'Node').replace('_', '')
            query = f"MERGE (n:{label} {{node_id: $node_id}}) SET n += $props"
            node_queries.append((query, {'node_id': str(node_id), 'props': props}))
        
        start_time = time.time()
        self.run_batch(node_queries, batch_size=1000, dry_run=dry_run)
        metrics['nodes_export_duration'] = time.time() - start_time
        self.logger.info("Exported nodes", count=len(node_queries))

        self.logger.info("Exporting relationships to Neo4j...")
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

        start_time = time.time()
        self.run_batch(rel_queries, batch_size=1000, dry_run=dry_run)
        metrics['rels_export_duration'] = time.time() - start_time
        self.logger.info("Exported relationships", count=len(rel_queries))

        return metrics

    def export_to_graphml(self, graph: nx.Graph, output_path: str):
        try:
            nx.write_graphml(graph, output_path)
            self.logger.info("Graph exported to GraphML", path=output_path)
        except Exception as e:
            self.logger.error("Failed to export to GraphML", error=str(e), path=output_path)
            raise

    def export_to_json(self, graph: nx.Graph, output_path: str):
        try:
            data = json_graph.node_link_data(graph)
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info("Graph exported to JSON", path=output_path)
        except Exception as e:
            self.logger.error("Failed to export to JSON", error=str(e), path=output_path)
            raise