# src/secrets/keyring_backend.py
import keyring
from keyring.errors import NoKeyringError
from .base_backend import SecretBackend

SERVICE_NAME = "ai-migration-tool"

class KeyringBackend(SecretBackend):
    def store_credential(self, user: str, password: str) -> None:
        try:
            keyring.set_password(SERVICE_NAME, user, password)
        except NoKeyringError as e:
            raise RuntimeError("No system keyring backend available. Install a backend (e.g., secretstorage, pywin32, or keyrings.alt).") from e
        except Exception as e:
            raise RuntimeError(f"Failed to store credential in keyring for user '{user}'.") from e