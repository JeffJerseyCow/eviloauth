"""An OAuth2.0 attack and security research tool."""
import tempfile
import importlib
from diskcache import Cache
from flask import Flask
from .module import MODULES

COMMANDS = {
    'configure': {'idp': {
        'entra_implicit_flow': None,
        'entra_code_flow': None
    }},
    'module': MODULES,
    'tokens': {
        'list': None,
        'set': None,  # Adding the 'set' subcommand for tokens
        # TODO: create add token wizard
        'add': None
    },
    'target': {
        'list': None,
        'set': None
    },
    'exit': None
}

app = Flask('eviloauth')
temp_dir = tempfile.mkdtemp()
cache = Cache(temp_dir)
cache.set('tokens', {})
cache.set('target', {})


def get_idps():
    from . import COMMANDS
    return list(COMMANDS.get('configure').get('idp').keys())


def load_modules():
    module_dict = {}
    for module in [f'eviloauth.module.{k}.{i}' for (k, v) in COMMANDS['module'].items() for i in v]:
        module_dict[module] = importlib.import_module(module)
        module_dict[module].__load__()
    return module_dict