# src/db/neo4j_manager.py

import logging
import yaml
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s')

class Neo4jManager:
    """
    Manages all interactions with the Neo4j database, including exporting
    the fully correlated graph.
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

    def _run_write_query(self, query, **kwargs):
        """Helper to run a write transaction with parameters."""
        with self.driver.session() as session:
            session.write_transaction(lambda tx: tx.run(query, **kwargs))

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
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:InstalledSoftware) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:StorageMount) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ConfigFile) REQUIRE n.unique_id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:ScheduledTask) REQUIRE n.unique_id IS UNIQUE"
        ]
        for constraint in constraints:
            try:
                self._run_write_query(constraint)
            except Exception as e:
                logging.warning(f"Could not create constraint (it may already exist): {e}")
        logging.info("Constraints created successfully.")

    def export_graph(self, db_manager):
        """
        Exports the entire dataset from SQLite to Neo4j, building a complete
        and correlated graph.
        """
        self.clear_database()
        self.create_constraints()

        # 1. Fetch all data from SQLite
        servers = db_manager.get_all_servers()
        apps = db_manager.get_all_applications()
        software = db_manager.get_all_installed_software()
        storage = db_manager.get_all_storage_mounts()
        configs = db_manager.get_all_config_files()
        tasks = db_manager.get_all_scheduled_tasks()
        open_files = db_manager.get_all_process_open_files()

        # 2. Create all nodes in batches
        logging.info("Exporting nodes to Neo4j...")
        self._create_nodes(servers, 'Server', 'id', {'hostname': 'hostname', 'ip': 'ip_address', 'os': 'os_name'})
        self._create_nodes(apps, 'Process', lambda r: f"{r['server_id']}_{r['pid']}", {'name': 'process_name', 'pid': 'pid', 'user': 'user', 'package': 'owning_package', 'server_id': 'server_id'})
        self._create_nodes(software, 'InstalledSoftware', 'id', {'name': 'name', 'version': 'version', 'server_id': 'server_id'})
        self._create_nodes(storage, 'StorageMount', 'id', {'mount_point': 'mount_point', 'type': 'storage_type', 'server_id': 'server_id'})
        self._create_nodes(configs, 'ConfigFile', 'id', {'path': 'file_path', 'server_id': 'server_id'})
        self._create_nodes(tasks, 'ScheduledTask', 'id', {'name': 'name', 'command': 'command', 'schedule': 'schedule', 'server_id': 'server_id'})
        logging.info("Node export complete.")

        # 3. Create all relationships
        logging.info("Exporting relationships to Neo4j...")
        self._create_relationships(apps, 'Process', lambda r: f"{r['server_id']}_{r['pid']}", 'Server', 'server_id', 'RUNS_ON')
        self._create_relationships(software, 'InstalledSoftware', 'id', 'Server', 'server_id', 'INSTALLED_ON')
        self._create_relationships(tasks, 'ScheduledTask', 'id', 'Server', 'server_id', 'SCHEDULED_ON')
        self._create_file_relationships(open_files, storage, configs)
        logging.info("Relationship export complete.")

    def _create_nodes(self, records, label, id_key_or_func, property_map):
        """
        *** FIX: Generic, robust function to create nodes. ***
        All logic is in Python; Cypher query is simple.
        """
        if not records: return
        
        query = f"UNWIND $batch AS properties CREATE (n:{label}) SET n = properties"
        
        batch = []
        for record in records:
            props = {neo4j_key: record.get(db_key) for neo4j_key, db_key in property_map.items()}
            
            # Calculate and add the unique_id as a string
            if callable(id_key_or_func):
                props['unique_id'] = id_key_or_func(record)
            else:
                props['unique_id'] = str(record.get(id_key_or_func))
            
            # Add server_id if it exists for relationship mapping
            if 'server_id' in record:
                props['server_id'] = record['server_id']
            
            batch.append(props)
        
        if batch:
            self._run_write_query(query, batch=batch)
            logging.info(f"Created {len(batch)} {label} nodes.")

    def _create_relationships(self, source_records, source_label, source_key_fn, target_label, target_key_field, rel_type):
        """
        *** FIX: Generic, robust function to create relationships. ***
        Ensures all IDs are handled as strings.
        """
        if not source_records: return

        query = f"""
        UNWIND $records AS record
        MATCH (source:{source_label} {{unique_id: record.source_id}})
        MATCH (target:{target_label} {{unique_id: record.target_id}})
        MERGE (source)-[:{rel_type}]->(target)
        """

        batch = []
        for record in source_records:
            source_id = source_key_fn(record) if callable(source_key_fn) else str(record.get(source_key_fn))
            target_id = str(record.get(target_key_field))
            batch.append({'source_id': source_id, 'target_id': target_id})
        
        if batch:
            self._run_write_query(query, records=batch)
            logging.info(f"Created {len(batch)} '{rel_type}' relationships from {source_label} to {target_label}.")

    def _create_file_relationships(self, open_files, storage, configs):
        """Create USES_STORAGE and USES_CONFIG relationships."""
        if not open_files: return

        # Create USES_STORAGE relationships
        storage_rels = []
        for f in open_files:
            for s in storage:
                if f['server_id'] == s['server_id'] and f['file_path'].startswith(s['mount_point']):
                    storage_rels.append({
                        'source_id': f"{f['server_id']}_{f['pid']}",
                        'target_id': str(s['id']) # Ensure target ID is a string
                    })
        if storage_rels:
            query = """
            UNWIND $rels AS rel
            MATCH (p:Process {unique_id: rel.source_id})
            MATCH (s:StorageMount {unique_id: rel.target_id})
            MERGE (p)-[:USES_STORAGE]->(s)
            """
            self._run_write_query(query, rels=storage_rels)
            logging.info(f"Created {len(storage_rels)} 'USES_STORAGE' relationships.")

        # Create USES_CONFIG relationships
        config_rels = []
        for f in open_files:
            for c in configs:
                if f['server_id'] == c['server_id'] and f['file_path'] == c['file_path']:
                    config_rels.append({
                        'source_id': f"{f['server_id']}_{f['pid']}",
                        'target_id': str(c['id']) # Ensure target ID is a string
                    })
        if config_rels:
            query = """
            UNWIND $rels AS rel
            MATCH (p:Process {unique_id: rel.source_id})
            MATCH (c:ConfigFile {unique_id: rel.target_id})
            MERGE (p)-[:USES_CONFIG]->(c)
            """
            self._run_write_query(query, rels=config_rels)
            logging.info(f"Created {len(config_rels)} 'USES_CONFIG' relationships.")