"""
Configuration management for Andrea library
Handles secure storage and retrieval of Aqua credentials
"""

import json
import os
import getpass
from pathlib import Path
import configparser
from cryptography.fernet import Fernet

# Configuration paths
CONFIG_DIR = Path.home() / '.aqua'
CONFIG_FILE = CONFIG_DIR / 'config.ini'
CREDS_FILE = CONFIG_DIR / 'credentials.enc'
KEY_FILE = CONFIG_DIR / '.key'


class ConfigManager:
    """Manages configuration and credentials for Aqua utilities"""
    
    def __init__(self):
        self.config_dir = CONFIG_DIR
        self.config_file = CONFIG_FILE
        self.creds_file = CREDS_FILE
        self.key_file = KEY_FILE
        self.ensure_config_dir()
    
    def ensure_config_dir(self):
        """Create config directory if it doesn't exist"""
        self.config_dir.mkdir(mode=0o700, exist_ok=True)
    
    def generate_key(self):
        """Generate encryption key for credentials"""
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        self.key_file.chmod(0o600)
        return key
    
    def get_key(self):
        """Get or create encryption key"""
        if self.key_file.exists():
            return self.key_file.read_bytes()
        return self.generate_key()
    
    def encrypt_credentials(self, creds_dict):
        """Encrypt credentials dictionary"""
        key = self.get_key()
        f = Fernet(key)
        creds_json = json.dumps(creds_dict)
        encrypted = f.encrypt(creds_json.encode())
        self.creds_file.write_bytes(encrypted)
        self.creds_file.chmod(0o600)
    
    def decrypt_credentials(self):
        """Decrypt credentials dictionary"""
        if not self.creds_file.exists():
            return None
        key = self.get_key()
        f = Fernet(key)
        encrypted = self.creds_file.read_bytes()
        decrypted = f.decrypt(encrypted)
        return json.loads(decrypted.decode())
    
    def save_config(self, profile_name, config_dict):
        """Save configuration for a profile"""
        config = configparser.ConfigParser()
        if self.config_file.exists():
            config.read(self.config_file)
        
        config[profile_name] = config_dict
        
        with open(self.config_file, 'w') as f:
            config.write(f)
        self.config_file.chmod(0o600)
    
    def load_config(self, profile_name='default'):
        """Load configuration for a profile"""
        if not self.config_file.exists():
            return None
        
        config = configparser.ConfigParser()
        config.read(self.config_file)
        
        if profile_name in config:
            return dict(config[profile_name])
        return None
    
    def list_profiles(self):
        """List available profiles"""
        if not self.config_file.exists():
            return []
        
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return [s for s in config.sections() if s != 'DEFAULT']
    
    def delete_profile(self, profile_name):
        """Delete a profile"""
        config = configparser.ConfigParser()
        config.read(self.config_file)
        
        if profile_name in config:
            config.remove_section(profile_name)
            with open(self.config_file, 'w') as f:
                config.write(f)
            return True
        return False


def load_profile_credentials(profile_name='default'):
    """Load credentials from saved profile and set environment variables"""
    config_mgr = ConfigManager()
    
    config = config_mgr.load_config(profile_name)
    if not config:
        return False
    
    creds = config_mgr.decrypt_credentials()
    if not creds:
        return False
    
    # Set environment variables
    if config.get('auth_method') == 'api_keys':
        os.environ['AQUA_KEY'] = creds['api_key']
        os.environ['AQUA_SECRET'] = creds['api_secret']
        os.environ['AQUA_ROLE'] = config['api_role']
        os.environ['AQUA_METHODS'] = config['api_methods']
        os.environ['AQUA_ENDPOINT'] = config['api_endpoint']
        os.environ['CSP_ENDPOINT'] = config['csp_endpoint']
    else:
        os.environ['AQUA_USER'] = creds['username']
        os.environ['AQUA_PASSWORD'] = creds['password']
        os.environ['CSP_ENDPOINT'] = config['csp_endpoint']
        if 'api_endpoint' in config:
            os.environ['AQUA_ENDPOINT'] = config['api_endpoint']
    
    return True


def test_connection(config, creds):
    """Test connection with provided credentials"""
    try:
        # Set environment variables temporarily
        old_env = {}
        
        if config['auth_method'] == 'api_keys':
            env_vars = {
                'AQUA_KEY': creds['api_key'],
                'AQUA_SECRET': creds['api_secret'],
                'AQUA_ROLE': config['api_role'],
                'AQUA_METHODS': config['api_methods'],
                'AQUA_ENDPOINT': config['api_endpoint'],
                'CSP_ENDPOINT': config['csp_endpoint']
            }
        else:
            env_vars = {
                'AQUA_USER': creds['username'],
                'AQUA_PASSWORD': creds['password'],
                'CSP_ENDPOINT': config['csp_endpoint']
            }
            if 'api_endpoint' in config:
                env_vars['AQUA_ENDPOINT'] = config['api_endpoint']
        
        # Save old values and set new ones
        for key, value in env_vars.items():
            old_env[key] = os.environ.get(key)
            os.environ[key] = value
        
        # Try to authenticate
        from .auth import authenticate
        token = authenticate(verbose=False)
        
        # Restore old environment
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        
        return bool(token)
    except Exception:
        # Restore old environment
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


def interactive_setup(profile_name='default'):
    """Interactive setup wizard for Aqua credentials"""
    print("=" * 60)
    print("Aqua Configuration Setup")
    print("=" * 60)
    print()
    
    config_mgr = ConfigManager()
    
    # Check if profile exists
    existing_config = config_mgr.load_config(profile_name)
    if existing_config:
        overwrite = input(f"Profile '{profile_name}' already exists. Overwrite? (y/N): ").lower()
        if overwrite != 'y':
            print("Setup cancelled.")
            return False
    
    print("Select authentication method:")
    print("1. API Keys (recommended for automation)")
    print("2. Username/Password")
    
    auth_method = input("\nEnter choice (1 or 2): ").strip()
    
    config = {}
    creds = {}
    
    if auth_method == '1':
        print("\n--- API Keys Authentication Setup ---")
        config['auth_method'] = 'api_keys'
        
        # Endpoint selection
        print("\nSelect Aqua environment:")
        print("1. US Region (api.cloudsploit.com)")
        print("2. EU-1 Region (eu-1.api.cloudsploit.com)")
        print("3. Asia Region (asia-1.api.cloudsploit.com)")
        print("4. Custom endpoint")
        
        endpoint_choice = input("\nEnter choice (1-4): ").strip()
        
        endpoints = {
            '1': 'https://api.cloudsploit.com',
            '2': 'https://eu-1.api.cloudsploit.com',
            '3': 'https://asia-1.api.cloudsploit.com'
        }
        
        if endpoint_choice in endpoints:
            config['api_endpoint'] = endpoints[endpoint_choice]
        else:
            config['api_endpoint'] = input("Enter API endpoint URL: ").strip()
        
        # CSP endpoint
        print("\nEnter your Aqua Console URL")
        print("Example: https://xyz.cloud.aquasec.com")
        config['csp_endpoint'] = input("Console URL: ").strip()
        
        # API credentials
        print("\nEnter API credentials (from Aqua Console > Settings > API Keys)")
        creds['api_key'] = input("API Key: ").strip()
        creds['api_secret'] = getpass.getpass("API Secret: ")
        
        # API role
        print("\nEnter API role name")
        api_role = input("API Role: ").strip()
        config['api_role'] = api_role
        
        # API methods
        config['api_methods'] = 'ANY'
        
    else:
        print("\n--- Username/Password Authentication Setup ---")
        config['auth_method'] = 'user_pass'
        
        # Check if SaaS or on-prem
        is_saas = input("Is this a SaaS deployment? (y/N): ").lower() == 'y'
        
        if is_saas:
            # Same endpoint selection as API keys
            print("\nSelect Aqua environment:")
            print("1. US Region (api.cloudsploit.com)")
            print("2. EU-1 Region (eu-1.api.cloudsploit.com)")
            print("3. Asia Region (asia-1.api.cloudsploit.com)")
            print("4. Custom endpoint")
            
            endpoint_choice = input("\nEnter choice (1-4): ").strip()
            
            endpoints = {
                '1': 'https://api.cloudsploit.com',
                '2': 'https://eu-1.api.cloudsploit.com',
                '3': 'https://asia-1.api.cloudsploit.com'
            }
            
            if endpoint_choice in endpoints:
                config['api_endpoint'] = endpoints[endpoint_choice]
            else:
                config['api_endpoint'] = input("Enter API endpoint URL: ").strip()
        
        # CSP endpoint
        print("\nEnter your Aqua Console URL")
        print("Example: https://xyz.cloud.aquasec.com or https://aqua.company.internal")
        config['csp_endpoint'] = input("Console URL: ").strip()
        
        # User credentials
        print("\nEnter user credentials")
        creds['username'] = input("Username/Email: ").strip()
        creds['password'] = getpass.getpass("Password: ")
    
    # Test connection
    print("\nTesting connection...")
    if test_connection(config, creds):
        print("✓ Connection successful!")
        
        # Save configuration
        save = input("\nSave this configuration? (Y/n): ").lower()
        if save != 'n':
            config_mgr.save_config(profile_name, config)
            config_mgr.encrypt_credentials(creds)
            print(f"\n✓ Configuration saved to profile '{profile_name}'")
            print(f"  Config file: {CONFIG_FILE}")
            print(f"  Encrypted credentials: {CREDS_FILE}")
            return True
        else:
            print("\nConfiguration not saved.")
            return False
    else:
        print("✗ Connection failed. Please check your credentials and try again.")
        return False


def list_profiles(verbose=True):
    """List available profiles with details"""
    config_mgr = ConfigManager()
    profiles = config_mgr.list_profiles()
    
    if verbose:
        if not profiles:
            print("No profiles configured.")
            return []
        
        print("Available profiles:")
        for profile in profiles:
            config = config_mgr.load_config(profile)
            auth_method = config.get('auth_method', 'unknown')
            endpoint = config.get('csp_endpoint', 'unknown')
            print(f"  - {profile} ({auth_method}, {endpoint})")
    
    return profiles