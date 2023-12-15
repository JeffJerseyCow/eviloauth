import tempfile
from flask import Flask
from diskcache import Cache
from .modules import ATTACK_MODULES

__version__ = '0.0.2'
flask_app = Flask('evil-oauth')

temp_dir = tempfile.mkdtemp()
cache = Cache(temp_dir)

OPAQUE_TOKEN_COUNT_KEY = "opaque_token_count"
MODULES = {
    'attack': ATTACK_MODULES,
    'exit': None
}
