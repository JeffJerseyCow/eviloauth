"""An OAuth2.0 attack and security research tool."""
import tempfile
import importlib
from diskcache import Cache
from flask import Flask
from .modules import MODULES
from prompt_toolkit.completion import NestedCompleter

token_commands = {
    'add': {
        'upn': None
        }, 
    'delete': None, 
    'list': None
}

COMMANDS = {
    'configure': {'idp': {
        'entra_implicit_flow': None,
        'entra_code_flow': None
    }},
    'modules': MODULES,
    'tokens': token_commands, 
    'exit': None
}

app = Flask('eviloauth')
temp_dir = tempfile.mkdtemp()
cache = Cache(temp_dir)

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

def get_completer():
    return completer