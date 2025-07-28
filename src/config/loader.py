# src/config/loader.py

import os
import yaml
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, Any

class ConfigLoader:
    def __init__(self, config_path: str = "knowledge_base.yaml"):
        self.config_path = Path(config_path)
        load_dotenv()  # Load .env if present

    def load(self) -> Dict[str, Any]:
        config = {}
        if self.config_path.exists():
            with self.config_path.open('r') as f:
                config = yaml.safe_load(f) or {}
        # Override with env vars and validate
        neo4j = config.get('neo4j', {})
        neo4j['uri'] = os.getenv('NEO4J_URI', neo4j.get('uri'))
        neo4j['user'] = os.getenv('NEO4J_USER', neo4j.get('user'))
        password = os.getenv('NEO4J_PASSWORD', neo4j.get('password'))
        if password.startswith('${') or not password:
            raise ValueError("NEO4J_PASSWORD environment variable not set or invalid. Set it to your actual Neo4j password.")
        neo4j['password'] = password
        config['neo4j'] = neo4j
        return config