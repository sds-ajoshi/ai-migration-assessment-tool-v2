# src/secrets/vault_backend.py
import os
import hvac
from .base_backend import SecretBackend

class VaultBackend(SecretBackend):
    def __init__(self):
        vault_url = os.getenv("VAULT_URL")
        vault_token = os.getenv("VAULT_TOKEN")
        if not vault_url or not vault_token:
            raise ValueError("VAULT_URL and VAULT_TOKEN environment variables must be set for Vault backend.")
        self.client = hvac.Client(url=vault_url, token=vault_token)
        if not self.client.is_authenticated():
            raise RuntimeError("Failed to authenticate with Vault.")

    def store_credential(self, user: str, password: str) -> None:
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=f"ai-migration-tool/{user}",
                secret={"password": password},
            )
        except Exception as e:
            raise RuntimeError(f"Failed to store credential in Vault for user '{user}'.") from e