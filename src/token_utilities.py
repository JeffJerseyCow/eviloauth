import base64
import json
from datetime import datetime, date
from . import cache

def decode_access_token(token):
    _, payload, _ = token.split('.')
    payload_decoded = base64.urlsafe_b64decode(add_padding(payload)).decode('utf-8')
    return json.loads(payload_decoded)

def add_padding(token_part):
    """Adds the required padding to the base64 encoded string."""
    return token_part + '=' * (4 - len(token_part) % 4)

def get_cache(cache_key):
    print(cache.get(cache_key))

def process_token(token):
    payload = decode_access_token(token)
    unique_name = payload.get('unique_name')
    if not unique_name:
        raise ValueError("Unique name not found in token payload")

    scope = payload.get('scp')
    time = datetime.now().strftime("%H:%M:%S")
    today = date.today().strftime("%d-%m-%Y")

    cache_key = 'user_data_' + unique_name
    cache_data = {
        "access_token": token,
        "scope": scope,
        "time": time,
        "date": today,
        "email_address": unique_name
    }

    cache.set(cache_key, cache_data)
    get_cache(cache_key)
    return cache_data
