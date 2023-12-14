from flask import Flask
import tempfile
from diskcache import Cache

__version__ = '0.0.2'
flask_app = Flask('evil-oauth')

temp_dir = tempfile.mkdtemp()
cache = Cache(temp_dir)