import unittest
from unittest.mock import patch, MagicMock
import os
import pandas as pd
import keyring
import sqlite3

# Add the src directory to the Python path to allow for imports
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

# Import the main application function and db manager
from main import discover
from db import db_manager

# --- Constants for Testing ---
TEST_DB_FILE = 'test_assessment.db'
TEST_INVENTORY_FILE = 'test_inventory.csv'
SERVICE_NAME = "ai-migration-tool"
LINUX_USER = "test_linux_user"
WIN_USER = "test_win_user"

class TestDiscoveryScenarios(unittest.TestCase):

    def setUp(self):
        """
        Set up the test environment before each test case runs.
        """
        # Create a dummy inventory file for all tests
        self.inventory_data = {
            'ip': ['10.0.0.1', '10.0.0.2'],
            'os_type': ['linux', 'windows'],
            'user': [LINUX_USER, WIN_USER]
        }
        df = pd.DataFrame(self.inventory_data)
        df.to_csv(TEST_INVENTORY_FILE, index=False)

        # Set dummy passwords in keyring
        keyring.set_password(SERVICE_NAME, LINUX_USER, "dummy_password")
        keyring.set_password(SERVICE_NAME, WIN_USER, "dummy_password")

        # Ensure the test database does not exist before a test
        if os.path.exists(TEST_DB_FILE):
            os.remove(TEST_DB_FILE)

    def tearDown(self):
        """
        Clean up the environment after each test case runs.
        """
        if os.path.exists(TEST_INVENTORY_FILE):
            os.remove(TEST_INVENTORY_FILE)
        
        if os.path.exists(TEST_DB_FILE):
            os.remove(TEST_DB_FILE)
            
        try:
            keyring.delete_password(SERVICE_NAME, LINUX_USER)
            keyring.delete_password(SERVICE_NAME, WIN_USER)
        except keyring.errors.NoKeyringError:
            pass # Ignore if no backend is available (e.g., in CI/CD)


    @patch('main.discover_host')
    @patch('db.db_manager.DB_FILE', TEST_DB_FILE)
    def test_tc1_happy_path(self, mock_discover_host):
        """
        TC-1: Tests the end-to-end discovery process for the happy path scenario.
        """
        print("\n--- Running TC-1: Happy Path Test ---")

        def side_effect_func(host_info):
            if host_info['os_type'] == 'linux':
                return {"ip": host_info['ip'], "status": "Success", "data": {"hostname": "linux-server", "cpu_cores": 4, "running_processes": [{"process_name": "sshd"}]}}
            else:
                return {"ip": host_info['ip'], "status": "Success", "data": {"hostname": "win-server", "cpu_cores": 8, "running_processes": [{"process_name": "winlogon.exe"}]}}
        
        mock_discover_host.side_effect = side_effect_func

        discover(inventory_file=TEST_INVENTORY_FILE, max_workers=2)

        self.assertTrue(os.path.exists(TEST_DB_FILE))
        conn = sqlite3.connect(TEST_DB_FILE)
        server_count = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
        app_count = conn.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
        conn.close()

        self.assertEqual(server_count, 2, "Should have discovered 2 servers.")
        self.assertEqual(app_count, 2, "Should have discovered 2 applications.")
        print("[PASS] TC-1: Happy Path successful.")

    @patch('main.discover_host')
    @patch('db.db_manager.DB_FILE', TEST_DB_FILE)
    def test_tc2_unreachable_host(self, mock_discover_host):
        """
        TC-2: Tests how the tool handles one successful and one failed host.
        """
        print("\n--- Running TC-2: Unreachable Host Test ---")

        def side_effect_func(host_info):
            if host_info['os_type'] == 'linux':
                return {"ip": host_info['ip'], "status": "Success", "data": {"hostname": "linux-server", "cpu_cores": 4, "running_processes": [{"process_name": "sshd"}]}}
            else:
                return {"ip": host_info['ip'], "status": "Failed", "data": "Connection timed out"}
        
        mock_discover_host.side_effect = side_effect_func

        discover(inventory_file=TEST_INVENTORY_FILE, max_workers=2)

        self.assertTrue(os.path.exists(TEST_DB_FILE))
        conn = sqlite3.connect(TEST_DB_FILE)
        server_count = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
        self.assertEqual(server_count, 1, "Should only have 1 (successful) server in DB.")
        conn.close()
        print("[PASS] TC-2: Unreachable Host test successful.")

    @patch('main.discover_host')
    @patch('db.db_manager.DB_FILE', TEST_DB_FILE)
    def test_tc3_auth_failure(self, mock_discover_host):
        """
        TC-3: Tests how the tool handles an authentication failure.
        """
        print("\n--- Running TC-3: Authentication Failure Test ---")

        def side_effect_func(host_info):
            # The Linux host will succeed
            if host_info['os_type'] == 'linux':
                return {"ip": host_info['ip'], "status": "Success", "data": {"hostname": "linux-server", "cpu_cores": 4, "running_processes": [{"process_name": "sshd"}]}}
            # The Windows host will fail with an auth error
            else:
                return {"ip": host_info['ip'], "status": "Failed", "data": "Authentication failed"}
        
        mock_discover_host.side_effect = side_effect_func

        discover(inventory_file=TEST_INVENTORY_FILE, max_workers=2)

        # Assertions: The DB should exist but only contain data for the successful host
        self.assertTrue(os.path.exists(TEST_DB_FILE), "Database file was not created.")
        
        conn = sqlite3.connect(TEST_DB_FILE)
        cursor = conn.cursor()

        # Should only be 1 server in the DB
        server_count = cursor.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
        self.assertEqual(server_count, 1, "Should only have 1 (successful) server in DB after auth failure.")
        print(f"[PASS] Correct number of successful servers ({server_count}) found in DB.")

        # Check that the successful server is the Linux one
        server_ip = cursor.execute("SELECT ip_address FROM servers").fetchone()[0]
        self.assertEqual(server_ip, self.inventory_data['ip'][0])
        print(f"[PASS] Correct server ({server_ip}) with valid auth found in DB.")

        conn.close()
        print("[PASS] TC-3: Authentication Failure test successful.")


if __name__ == '__main__':
    unittest.main()