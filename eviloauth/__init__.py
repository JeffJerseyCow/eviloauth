"""An OAuth2.0 attack and security research tool."""
import tempfile
import importlib
from diskcache import Cache
from flask import Flask
from .modules import MODULES
from prompt_toolkit.completion import NestedCompleter

# Define the structure of your commands for auto-completion
token_commands = {
    'add': {
        'upn': None
        },  # Assuming no further subcommands for 'add'
    'delete': None,  # Assuming no further subcommands for 'delete'
    'list': None,  # Assuming no further subcommands for 'list'
}

COMMANDS = {
    'configure': {'idp': {
        'entra_implicit_flow': None,
        'entra_code_flow': None
    }},
    'modules': MODULES,
    'tokens': token_commands,  # Include the token command structure
    'exit': None
}

app = Flask('eviloauth')
temp_dir = tempfile.mkdtemp()
cache = Cache(temp_dir)

# Initialize the completer with the command structure
completer = NestedCompleter.from_nested_dict(COMMANDS)

def get_idps():
    from . import COMMANDS
    return list(COMMANDS.get('configure').get('idp').keys())

def load_modules():
    module_dict = {}
    for module in [f'eviloauth.modules.{k}.{i}' for (k, v) in COMMANDS['modules'].items() for i in v]:
        module_dict[module] = importlib.import_module(module)
        module_dict[module].__load__()
    return module_dict

# Expose the completer for use in the command prompt session
def get_completer():
    return completer