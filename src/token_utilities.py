import base64
import json
from datetime import datetime, date
from . import cache

OPAQUE_TOKEN_COUNT_KEY = "opaque_token_count"

def decode_access_token(token):
    _, payload, _ = token.split('.')
    payload_decoded = base64.urlsafe_b64decode(add_padding(payload)).decode('utf-8')
    return json.loads(payload_decoded)

def add_padding(token_part):
    """Adds the required padding to the base64 encoded string."""
    return token_part + '=' * (4 - len(token_part) % 4)

def get_cache(cache_key):
    return cache.get(cache_key)

def process_token(token):
    parts = token.split('.')
    if len(parts) == 3:
        try:
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
            access_token = cache_key, cache_data
            return access_token

        except Exception as e:
            opaque_token_count = cache.get(OPAQUE_TOKEN_COUNT_KEY, 0) + 1
            cache.set(OPAQUE_TOKEN_COUNT_KEY, opaque_token_count)

            opaque_key = f'opaque_{opaque_token_count}'
            cache.set(opaque_key, token)
            raise e  
    else:
        opaque_token_count = cache.get(OPAQUE_TOKEN_COUNT_KEY, 0) + 1
        cache.set(OPAQUE_TOKEN_COUNT_KEY, opaque_token_count)

        opaque_key = f'opaque_{opaque_token_count}'
        time = datetime.now().strftime("%H:%M:%S")
        today = date.today().strftime("%d-%m-%Y")
        opaque_data = {
            "opaque_token": token,
            "time": time,
            "date": today
        }

        cache.set(opaque_key, opaque_data)
        return {"opaque_key": opaque_key, "data": opaque_data}