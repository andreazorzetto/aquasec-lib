"""
Basic tests for Aqua VM Extraction Utility
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import the main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aqua_vm_extract


class TestVersion(unittest.TestCase):
    """Test version functionality"""
    
    def test_version_display(self):
        """Test that version is displayed correctly"""
        with patch('sys.argv', ['aqua_vm_extract.py', '--version']):
            with patch('sys.exit') as mock_exit:
                with patch('builtins.print') as mock_print:
                    aqua_vm_extract.main()
                    mock_print.assert_called_with(f"Aqua VM Extraction Utility version {aqua_vm_extract.__version__}")
                    mock_exit.assert_called_with(0)


class TestGlobalArgs(unittest.TestCase):
    """Test global argument extraction"""
    
    def test_extract_global_args_verbose(self):
        """Test extracting verbose flag"""
        args = ['vm', 'list', '-v']
        global_args, filtered_args = aqua_vm_extract.extract_global_args(args)
        
        self.assertTrue(global_args['verbose'])
        self.assertEqual(filtered_args, ['vm', 'list'])
    
    def test_extract_global_args_debug(self):
        """Test extracting debug flag"""
        args = ['-d', 'vm', 'count']
        global_args, filtered_args = aqua_vm_extract.extract_global_args(args)
        
        self.assertTrue(global_args['debug'])
        self.assertEqual(filtered_args, ['vm', 'count'])
    
    def test_extract_global_args_profile(self):
        """Test extracting profile option"""
        args = ['vm', 'list', '-p', 'test-profile']
        global_args, filtered_args = aqua_vm_extract.extract_global_args(args)
        
        self.assertEqual(global_args['profile'], 'test-profile')
        self.assertEqual(filtered_args, ['vm', 'list'])
    
    def test_extract_global_args_mixed(self):
        """Test extracting mixed global arguments"""
        args = ['-v', 'vm', 'list', '--no-enforcer', '-d', '-p', 'prod']
        global_args, filtered_args = aqua_vm_extract.extract_global_args(args)
        
        self.assertTrue(global_args['verbose'])
        self.assertTrue(global_args['debug'])
        self.assertEqual(global_args['profile'], 'prod')
        self.assertEqual(filtered_args, ['vm', 'list', '--no-enforcer'])


class TestVMFiltering(unittest.TestCase):
    """Test VM filtering logic"""
    
    def setUp(self):
        """Set up test data"""
        self.mock_vms = [
            {
                'id': 'vm1',
                'name': 'test-vm-1',
                'covered_by': ['agentless', 'cspm'],
                'cloud_provider': 'AWS',
                'region': 'us-west-1',
                'highest_risk': 'high'
            },
            {
                'id': 'vm2', 
                'name': 'test-vm-2',
                'covered_by': ['vm_enforcer'],
                'cloud_provider': 'Azure',
                'region': 'eastus',
                'highest_risk': 'medium'
            },
            {
                'id': 'vm3',
                'name': 'test-vm-3', 
                'covered_by': ['agentless'],
                'cloud_provider': 'AWS',
                'region': 'us-east-1',
                'highest_risk': 'critical'
            },
            {
                'id': 'vm4',
                'name': 'test-vm-4',
                'covered_by': ['host_enforcer', 'cspm'],
                'cloud_provider': 'GCP',
                'region': 'us-central1',
                'highest_risk': 'low'
            }
        ]
    
    def test_filter_vms_without_enforcer(self):
        """Test filtering VMs without VM enforcer"""
        from aquasec import filter_vms_by_coverage
        
        # VMs without vm_enforcer, host_enforcer, aqua_enforcer, or agent
        excluded_types = ['vm_enforcer', 'host_enforcer', 'aqua_enforcer', 'agent']
        filtered = filter_vms_by_coverage(self.mock_vms, excluded_types=excluded_types)
        
        # Should return vm1 and vm3 (only agentless coverage)
        self.assertEqual(len(filtered), 2)
        vm_ids = [vm['id'] for vm in filtered]
        self.assertIn('vm1', vm_ids)
        self.assertIn('vm3', vm_ids)
        self.assertNotIn('vm2', vm_ids)  # Has vm_enforcer
        self.assertNotIn('vm4', vm_ids)  # Has host_enforcer
    
    def test_filter_vms_by_cloud_provider(self):
        """Test filtering VMs by cloud provider"""
        from aquasec import filter_vms_by_cloud_provider
        
        aws_vms = filter_vms_by_cloud_provider(self.mock_vms, ['AWS'])
        self.assertEqual(len(aws_vms), 2)
        
        azure_vms = filter_vms_by_cloud_provider(self.mock_vms, ['Azure'])
        self.assertEqual(len(azure_vms), 1)
        
        multi_cloud_vms = filter_vms_by_cloud_provider(self.mock_vms, ['AWS', 'GCP'])
        self.assertEqual(len(multi_cloud_vms), 3)
    
    def test_filter_vms_by_region(self):
        """Test filtering VMs by region"""
        from aquasec import filter_vms_by_region
        
        us_west_vms = filter_vms_by_region(self.mock_vms, ['us-west-1'])
        self.assertEqual(len(us_west_vms), 1)
        
        multiple_regions = filter_vms_by_region(self.mock_vms, ['us-west-1', 'eastus'])
        self.assertEqual(len(multiple_regions), 2)
    
    def test_filter_vms_by_risk_level(self):
        """Test filtering VMs by risk level"""
        from aquasec import filter_vms_by_risk_level
        
        high_risk_vms = filter_vms_by_risk_level(self.mock_vms, ['high'])
        self.assertEqual(len(high_risk_vms), 1)
        
        critical_high_vms = filter_vms_by_risk_level(self.mock_vms, ['critical', 'high'])
        self.assertEqual(len(critical_high_vms), 2)


class TestCSVExport(unittest.TestCase):
    """Test CSV export functionality"""
    
    def test_export_vms_to_csv(self):
        """Test CSV export creates file with correct structure"""
        import tempfile
        import csv
        
        mock_vms = [{
            'id': 'test-vm-1',
            'name': 'Test VM',
            'cloud_provider': 'AWS',
            'region': 'us-west-1',
            'os': 'ubuntu 20.04',
            'highest_risk': 'high',
            'covered_by': ['agentless'],
            'enforcer_group': 'default agentless group',
            'type': 'agentless',
            'compliant': False,
            'vulnerability_risk': 'high',
            'cloud_info': {
                'vm_id': 'i-1234567890',
                'vm_account_id': '123456789',
                'vm_public_ips': ['1.2.3.4'],
                'vm_private_ips': ['10.0.1.100']
            }
        }]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
            aqua_vm_extract.export_vms_to_csv(mock_vms, tmp.name)
            
            # Read back the CSV and verify structure
            with open(tmp.name, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
                
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row['name'], 'Test VM')
                self.assertEqual(row['cloud_provider'], 'AWS')
                self.assertEqual(row['covered_by'], 'agentless')
                self.assertEqual(row['vm_id'], 'i-1234567890')
            
            # Clean up
            os.unlink(tmp.name)


class TestMainFunction(unittest.TestCase):
    """Test main function behavior"""
    
    @patch('aqua_vm_extract.authenticate')
    @patch('aqua_vm_extract.load_profile_credentials')
    @patch.dict(os.environ, {'AQUA_USER': 'test', 'CSP_ENDPOINT': 'https://test.cloud.aquasec.com'})
    def test_main_no_command(self, mock_load_creds, mock_auth):
        """Test main function with no command shows help"""
        with patch('sys.argv', ['aqua_vm_extract.py']):
            with patch('sys.exit') as mock_exit:
                with patch('builtins.print'):
                    aqua_vm_extract.main()
                    mock_exit.assert_called_with(1)
    
    def test_main_setup_command(self):
        """Test main function with setup command"""
        with patch('sys.argv', ['aqua_vm_extract.py', 'setup']):
            with patch('aqua_vm_extract.interactive_setup') as mock_setup:
                with patch('sys.exit') as mock_exit:
                    mock_setup.return_value = True
                    aqua_vm_extract.main()
                    mock_setup.assert_called_once()
                    mock_exit.assert_called_with(0)


if __name__ == '__main__':
    unittest.main()