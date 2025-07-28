# src/agents/base_agent.py

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseIngestionAgent(ABC):
    """
    Abstract base class defining the interface for ingestion agents.
    Subclasses must implement all abstract methods to support specific platforms (e.g., Linux, Windows, PostgreSQL).
    """

    def __init__(self, host_info: Dict[str, Any], config: Dict[str, Any]):
        """
        Initializes the agent with host metadata and configuration.

        Args:
            host_info: Dictionary containing host details (e.g., {'ip': str, 'user': str, 'os_type': str}).
            config: Dictionary from knowledge_base.yaml or environment, containing discovery settings.
        """
        self.host_info = host_info
        self.config = config

    @abstractmethod
    def collect_all(self) -> List[Dict[str, Any]]:
        """
        Orchestrates the full phased data collection and returns all discovered entities.

        Returns:
            List[Dict[str, Any]]: List of records with 'type' key (e.g., 'Server', 'Application').
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_os(self) -> Dict[str, Any]:
        """
        Gathers OS metadata (e.g., hostname, version).

        Returns:
            Dict[str, Any]: OS details dictionary.
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_processes(self) -> List[Dict[str, Any]]:
        """
        Gathers running processes (e.g., PID, user, binary path).

        Returns:
            List[Dict[str, Any]]: List of process records.
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_network(self) -> Dict[str, Any]:
        """
        Gathers network details (e.g., open ports, interfaces, routes).

        Returns:
            Dict[str, Any]: Network configuration dictionary.
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_software(self) -> List[Dict[str, Any]]:
        """
        Gathers installed software/packages.

        Returns:
            List[Dict[str, Any]]: List of software records.
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_storage(self) -> List[Dict[str, Any]]:
        """
        Gathers storage details (e.g., mount points, disks).

        Returns:
            List[Dict[str, Any]]: List of storage records.
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_perf_metrics(self) -> List[Dict[str, Any]]:
        """
        Gathers performance metrics based on config.

        Returns:
            List[Dict[str, Any]]: List of metric records.
        """
        raise NotImplementedError

    @abstractmethod
    def _discover_config_files(self) -> List[Dict[str, Any]]:
        """
        Parses predefined config files from config paths/regex.

        Returns:
            List[Dict[str, Any]]: List of parsed config value records.
        """
        raise NotImplementedError