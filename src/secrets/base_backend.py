# src/secrets/base_backend.py
from abc import ABC, abstractmethod

class SecretBackend(ABC):
    @abstractmethod
    def store_credential(self, user: str, password: str) -> None:
        pass