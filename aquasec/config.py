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

# Check if we can use inquirer
try:
    import inquirer
    HAS_INQUIRER = True  # Let it try and fail gracefully if needed
    # Debug print to verify import
    import os
    if os.environ.get('AQUA_DEBUG'):
        print(f"DEBUG: Successfully imported inquirer, HAS_INQUIRER = {HAS_INQUIRER}")
except ImportError as e:
    HAS_INQUIRER = False
    import os
    if os.environ.get('AQUA_DEBUG'):
        print(f"DEBUG: Failed to import inquirer: {e}, HAS_INQUIRER = {HAS_INQUIRER}")

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
    
    def encrypt_credentials(self, creds_dict, profile_name='default'):
        """Encrypt credentials dictionary for a specific profile"""
        # Load existing credentials or create new structure
        all_creds = {}
        if self.creds_file.exists():
            try:
                existing = self.decrypt_all_credentials()
                if existing:
                    # Check if it's old format (direct credentials)
                    if 'username' in existing or 'api_key' in existing:
                        # Migrate old format to new format under 'default'
                        all_creds = {'default': existing}
                    else:
                        # Already in new format
                        all_creds = existing
            except:
                # If decryption fails, start fresh
                pass
        
        # Update credentials for this profile
        all_creds[profile_name] = creds_dict
        
        # Encrypt and save all credentials
        key = self.get_key()
        f = Fernet(key)
        creds_json = json.dumps(all_creds)
        encrypted = f.encrypt(creds_json.encode())
        self.creds_file.write_bytes(encrypted)
        self.creds_file.chmod(0o600)
    
    def decrypt_credentials(self, profile_name='default'):
        """Decrypt credentials dictionary for a specific profile"""
        all_creds = self.decrypt_all_credentials()
        if not all_creds:
            return None
        
        # Handle migration from old format
        if 'username' in all_creds or 'api_key' in all_creds:
            # Old format - return as-is only if requesting default profile
            if profile_name == 'default':
                return all_creds
            return None
        
        # New format - return specific profile
        return all_creds.get(profile_name)
    
    def decrypt_all_credentials(self):
        """Decrypt entire credentials file"""
        if not self.creds_file.exists():
            return None
        try:
            key = self.get_key()
            f = Fernet(key)
            encrypted = self.creds_file.read_bytes()
            decrypted = f.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except:
            return None
    
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
        """Delete a profile and its credentials"""
        # Delete from config
        config = configparser.ConfigParser()
        config.read(self.config_file)
        
        deleted = False
        if profile_name in config:
            config.remove_section(profile_name)
            with open(self.config_file, 'w') as f:
                config.write(f)
            deleted = True
        
        # Delete from credentials
        all_creds = self.decrypt_all_credentials()
        if all_creds and profile_name in all_creds:
            del all_creds[profile_name]
            # Re-encrypt without the deleted profile
            if all_creds:  # Only save if there are remaining profiles
                key = self.get_key()
                f = Fernet(key)
                creds_json = json.dumps(all_creds)
                encrypted = f.encrypt(creds_json.encode())
                self.creds_file.write_bytes(encrypted)
                self.creds_file.chmod(0o600)
            else:
                # No more profiles, remove the file
                self.creds_file.unlink(missing_ok=True)
            deleted = True
        
        return deleted
    
    def set_default_profile(self, profile_name):
        """Set a profile as the default"""
        config = configparser.ConfigParser()
        if self.config_file.exists():
            config.read(self.config_file)
        if 'DEFAULT' not in config:
            config['DEFAULT'] = {}
        config['DEFAULT']['default_profile'] = profile_name
        with open(self.config_file, 'w') as f:
            config.write(f)
        self.config_file.chmod(0o600)
    
    def get_default_profile(self):
        """Get the default profile name"""
        if not self.config_file.exists():
            return 'default'
        config = configparser.ConfigParser()
        config.read(self.config_file)
        return config['DEFAULT'].get('default_profile', 'default')


def load_profile_credentials(profile_name='default'):
    """Load credentials from saved profile and set environment variables"""
    config_mgr = ConfigManager()
    
    # If profile_name is 'default', check if a different default is configured
    if profile_name == 'default':
        actual_default = config_mgr.get_default_profile()
        if actual_default != 'default' and actual_default in config_mgr.list_profiles():
            profile_name = actual_default
    
    config = config_mgr.load_config(profile_name)
    if not config:
        return False, profile_name
    
    creds = config_mgr.decrypt_credentials(profile_name)
    if not creds:
        return False, profile_name
    
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
    
    return True, profile_name


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


def interactive_setup(profile_name=None, debug=False):
    """Interactive setup wizard for Aqua credentials"""
    print("=" * 60)
    print("Aqua Configuration Setup")
    print("=" * 60)
    print()
    
    if debug:
        print(f"DEBUG: HAS_INQUIRER = {HAS_INQUIRER}")
    
    if debug and HAS_INQUIRER:
        print("DEBUG: Keyboard navigation is available")
    elif debug:
        print("DEBUG: Keyboard navigation not available (using numbered menus)")
    
    config_mgr = ConfigManager()
    
    # Ask for profile name if not provided
    if not profile_name:
        profile_name = input("Enter profile name (Default): ").strip() or 'default'
    
    # Check if profile exists
    existing_config = config_mgr.load_config(profile_name)
    if existing_config:
        overwrite = False
        if HAS_INQUIRER:
            try:
                questions = [
                    inquirer.Confirm('overwrite',
                                    message=f"Profile '{profile_name}' already exists. Overwrite?",
                                    default=False)
                ]
                answers = inquirer.prompt(questions)
                overwrite = answers['overwrite']
            except Exception as e:
                # Fall back to simple input if inquirer fails
                if debug:
                    print(f"DEBUG: Inquirer failed for overwrite prompt: {e}")
                overwrite_input = input(f"Profile '{profile_name}' already exists. Overwrite? (y/N): ").lower()
                overwrite = overwrite_input == 'y'
        else:
            overwrite_input = input(f"Profile '{profile_name}' already exists. Overwrite? (y/N): ").lower()
            overwrite = overwrite_input == 'y'
        
        if not overwrite:
            print("Setup cancelled.")
            return False
    
    # Authentication method selection
    config = {}
    creds = {}
    
    auth_selected = False
    if HAS_INQUIRER:
        try:
            auth_methods = [
                ('Username/Password', 'user_pass'),
                ('API Keys', 'api_keys')
            ]
            questions = [
                inquirer.List('auth_method',
                              message="Select authentication method",
                              choices=[name for name, _ in auth_methods])
            ]
            answers = inquirer.prompt(questions)
            selected_auth = next((method for name, method in auth_methods if name == answers['auth_method']), 'user_pass')
            config['auth_method'] = selected_auth
            auth_selected = True
        except Exception as e:
            # Fall back to numbered menu if inquirer fails
            if debug:
                print(f"DEBUG: Inquirer failed for auth method selection: {e}")
            auth_selected = False
    
    if not auth_selected:
        print("Select authentication method:")
        print("1. Username/Password")
        print("2. API Keys")
        auth_choice = input("\nEnter choice (1-2): ").strip()
        
        if auth_choice == '2':
            config['auth_method'] = 'api_keys'
        else:
            config['auth_method'] = 'user_pass'
    
    if config['auth_method'] == 'api_keys':
        print("\n--- API Key Authentication Setup ---")
    else:
        print("\n--- Username/Password Authentication Setup ---")
    
    # For API keys, always need API endpoint. For user/pass, only for SaaS
    need_endpoint = config['auth_method'] == 'api_keys'
    if not need_endpoint:
        if HAS_INQUIRER:
            try:
                questions = [
                    inquirer.Confirm('is_saas',
                                    message="Is this a SaaS deployment?",
                                    default=True)
                ]
                answers = inquirer.prompt(questions)
                need_endpoint = answers['is_saas']
            except Exception as e:
                # Fall back to simple input
                if debug:
                    print(f"DEBUG: Inquirer failed for SaaS prompt: {e}")
                need_endpoint = input("Is this a SaaS deployment? (Y/n): ").lower() != 'n'
        else:
            need_endpoint = input("Is this a SaaS deployment? (Y/n): ").lower() != 'n'
    
    if need_endpoint:
        # Endpoint selection
        endpoint_selected = False
        if HAS_INQUIRER:
            try:
                # Interactive menu with arrow keys
                endpoints = [
                    ('US Region (api.cloudsploit.com)', 'https://api.cloudsploit.com'),
                    ('EU-1 Region (eu-1.api.cloudsploit.com)', 'https://eu-1.api.cloudsploit.com'),
                    ('Asia Region (asia-1.api.cloudsploit.com)', 'https://asia-1.api.cloudsploit.com'),
                    ('Custom endpoint', 'custom')
                ]
                
                questions = [
                    inquirer.List('endpoint',
                                  message="Select Aqua environment",
                                  choices=[name for name, _ in endpoints],
                                  )
                ]
                answers = inquirer.prompt(questions)
                
                # Get the URL based on selection
                selected = next((url for name, url in endpoints if name == answers['endpoint']), None)
                if selected == 'custom':
                    config['api_endpoint'] = input("Enter API endpoint URL: ").strip()
                else:
                    config['api_endpoint'] = selected
                endpoint_selected = True
            except Exception as e:
                # Fall back to numbered menu
                if debug:
                    print(f"DEBUG: Inquirer failed for endpoint selection: {e}")
                endpoint_selected = False
        
        if not endpoint_selected:
            # Fallback to numbered menu
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
    
    # Collect credentials based on auth method
    if config['auth_method'] == 'api_keys':
        print("\nEnter API credentials")
        creds['api_key'] = input("API Key: ").strip()
        creds['api_secret'] = getpass.getpass("API Secret: ")
        
        # API role and methods
        print("\nAPI Configuration")
        config['api_role'] = input("API Role (default: Administrator): ").strip() or 'Administrator'
        config['api_methods'] = input("API Methods (default: ANY): ").strip() or 'ANY'
    else:
        print("\nEnter user credentials")
        creds['username'] = input("Username/Email: ").strip()
        creds['password'] = getpass.getpass("Password: ")
    
    # Test connection
    print("\nTesting connection...")
    if test_connection(config, creds):
        print("✓ Connection successful!")
        
        # Save configuration
        should_save = True
        if HAS_INQUIRER:
            try:
                questions = [
                    inquirer.Confirm('save',
                                    message="Save this configuration?",
                                    default=True)
                ]
                answers = inquirer.prompt(questions)
                should_save = answers['save']
            except Exception as e:
                # Fall back to simple input
                if debug:
                    print(f"DEBUG: Inquirer failed for save prompt: {e}")
                save = input("\nSave this configuration? (Y/n): ").lower()
                should_save = save != 'n'
        else:
            save = input("\nSave this configuration? (Y/n): ").lower()
            should_save = save != 'n'
        
        if should_save:
            config_mgr.save_config(profile_name, config)
            config_mgr.encrypt_credentials(creds, profile_name)
            print(f"\n✓ Configuration saved to profile '{profile_name}'")
            print(f"  Config file: {CONFIG_FILE}")
            print(f"  Encrypted credentials: {CREDS_FILE}")
            
            # Ask about default profile
            profiles = config_mgr.list_profiles()
            if len(profiles) == 1:
                # First profile, automatically set as default
                config_mgr.set_default_profile(profile_name)
                print(f"\n✓ '{profile_name}' set as default profile (first profile)")
            else:
                # Ask if should be default
                should_set_default = False
                if HAS_INQUIRER:
                    try:
                        questions = [
                            inquirer.Confirm('set_default',
                                            message=f"Set '{profile_name}' as the default profile?",
                                            default=False)
                        ]
                        answers = inquirer.prompt(questions)
                        should_set_default = answers['set_default']
                    except Exception as e:
                        # Fall back to simple input
                        if debug:
                            print(f"DEBUG: Inquirer failed for default profile prompt: {e}")
                        set_default = input(f"\nSet '{profile_name}' as the default profile? (y/N): ").lower()
                        should_set_default = set_default == 'y'
                else:
                    set_default = input(f"\nSet '{profile_name}' as the default profile? (y/N): ").lower()
                    should_set_default = set_default == 'y'
                
                if should_set_default:
                    config_mgr.set_default_profile(profile_name)
                    print(f"✓ '{profile_name}' set as default profile")
            
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
        
        from prettytable import PrettyTable
        
        table = PrettyTable()
        table.field_names = ["Profile", "Auth Method", "Console URL", "Credentials", "Default"]
        table.align["Profile"] = "l"
        table.align["Auth Method"] = "l"
        table.align["Console URL"] = "l"
        table.align["Credentials"] = "l"
        table.align["Default"] = "c"
        
        default_profile = config_mgr.get_default_profile()
        
        for profile in profiles:
            profile_info = get_profile_info(profile)
            
            # Format credentials column
            if profile_info.get('credentials_ref'):
                creds_display = f"Present ({profile_info['credentials_ref']})"
            else:
                creds_display = "Missing"
            
            # Truncate long URLs for display
            endpoint = profile_info.get('csp_endpoint', 'unknown')
            if len(endpoint) > 40:
                endpoint = endpoint[:37] + "..."
            
            table.add_row([
                profile_info['name'],
                profile_info.get('auth_method', 'unknown'),
                endpoint,
                creds_display,
                "✓" if profile_info['is_default'] else ""
            ])
        
        print(table)
    
    return profiles


def get_profile_info(profile_name):
    """Get basic profile information"""
    import hashlib
    
    config_mgr = ConfigManager()
    
    if profile_name not in config_mgr.list_profiles():
        return None
    
    config = config_mgr.load_config(profile_name)
    creds = config_mgr.decrypt_credentials(profile_name)
    
    info = {
        'name': profile_name,
        'auth_method': config.get('auth_method', 'unknown') if config else 'unknown',
        'csp_endpoint': config.get('csp_endpoint', 'unknown') if config else 'unknown',
        'is_default': config_mgr.get_default_profile() == profile_name
    }
    
    # Add credential reference
    if creds:
        # Create a hash of the credentials to identify them without exposing values
        if config.get('auth_method') == 'api_keys':
            # For API keys, hash the api_key
            cred_string = creds.get('api_key', '')
        else:
            # For username/password, hash the username
            cred_string = creds.get('username', '')
        
        if cred_string:
            # Create a short hash identifier (first 8 chars of SHA256)
            hash_obj = hashlib.sha256(cred_string.encode())
            info['credentials_ref'] = hash_obj.hexdigest()[:8]
        else:
            info['credentials_ref'] = None
    else:
        info['credentials_ref'] = None
    
    # Add api_endpoint if it exists (for SaaS deployments)
    if config and 'api_endpoint' in config:
        info['api_endpoint'] = config['api_endpoint']
    
    return info


def get_all_profiles_info():
    """Get information for all profiles"""
    config_mgr = ConfigManager()
    profiles = config_mgr.list_profiles()
    
    profile_data = []
    for profile in profiles:
        profile_info = get_profile_info(profile)
        if profile_info:
            profile_data.append(profile_info)
    
    return profile_data


def format_profile_info(profile_info, format='json'):
    """Format profile information for display
    
    Args:
        profile_info: Profile info dict from get_profile_info()
        format: 'json' or 'text' output format
    
    Returns:
        Formatted string for display
    """
    if format == 'json':
        import json
        return json.dumps(profile_info, indent=2)
    elif format == 'text':
        lines = []
        lines.append(f"Profile: {profile_info['name']}")
        lines.append(f"Authentication: {profile_info['auth_method']}")
        lines.append(f"Console URL: {profile_info['csp_endpoint']}")
        if 'api_endpoint' in profile_info:
            lines.append(f"API Endpoint: {profile_info['api_endpoint']}")
        if profile_info.get('credentials_ref'):
            lines.append(f"Credentials: Present (ref: {profile_info['credentials_ref']})")
        else:
            lines.append(f"Credentials: Missing")
        lines.append(f"Is Default: {'Yes' if profile_info['is_default'] else 'No'}")
        return '\n'.join(lines)
    else:
        raise ValueError(f"Unsupported format: {format}")


def delete_profile_with_result(profile_name):
    """Delete a profile and return structured result
    
    Returns:
        dict: Result with action, profile, success, and optional error
    """
    config_mgr = ConfigManager()
    
    if profile_name not in config_mgr.list_profiles():
        return {
            "action": "delete",
            "profile": profile_name,
            "success": False,
            "error": "Profile not found"
        }
    
    success = config_mgr.delete_profile(profile_name)
    
    return {
        "action": "delete",
        "profile": profile_name,
        "success": success
    }


def set_default_profile_with_result(profile_name):
    """Set default profile and return structured result
    
    Returns:
        dict: Result with action, profile, success, and optional error
    """
    config_mgr = ConfigManager()
    
    try:
        config_mgr.set_default_profile(profile_name)
        return {
            "action": "set-default",
            "profile": profile_name,
            "success": True
        }
    except ValueError as e:
        return {
            "action": "set-default",
            "profile": profile_name,
            "success": False,
            "error": str(e)
        }


def profile_not_found_response(profile_name, format='json'):
    """Generate profile not found error response
    
    Args:
        profile_name: Name of the profile that wasn't found
        format: 'json' or 'text' output format
    
    Returns:
        Formatted error message
    """
    if format == 'json':
        import json
        return json.dumps({"error": f"Profile '{profile_name}' not found"})
    else:
        return f"Profile '{profile_name}' not found"


def profile_operation_response(action, profile_name, success, error=None, format='json'):
    """Generate response for profile operations
    
    Args:
        action: The action performed (e.g., 'delete', 'set-default')
        profile_name: Name of the profile
        success: Boolean indicating success
        error: Optional error message
        format: 'json' or 'text' output format
    
    Returns:
        Formatted response message
    """
    if format == 'json':
        import json
        result = {
            "action": action,
            "profile": profile_name,
            "success": success
        }
        if error:
            result["error"] = error
        return json.dumps(result)
    else:
        if success:
            if action == 'delete':
                return f"Profile '{profile_name}' deleted successfully"
            elif action == 'set-default':
                return f"Profile '{profile_name}' set as default"
            else:
                return f"Operation '{action}' on profile '{profile_name}' successful"
        else:
            if error:
                return f"Failed to {action} profile '{profile_name}': {error}"
            else:
                return f"Failed to {action} profile '{profile_name}'"