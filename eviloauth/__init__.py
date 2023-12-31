"""An OAuth2.0 attack and security research tool."""
import tempfile
from diskcache import Cache
from flask import Flask
from .module import MODULES

MODULES = {
    'module': MODULES,
    'tokens': None,
    'exit': None
}

app = Flask('eviloauth')
temp_dir = tempfile.mkdtemp()
cache = Cache(temp_dir)
cache.set('tokens', {})
