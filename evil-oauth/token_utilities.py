import base64
import json
import logging
from datetime import datetime, date
from . import cache

def decode_access_token(payload):
    payload_decoded = base64.urlsafe_b64decode(add_padding(payload)).decode('utf-8')
    return json.loads(payload_decoded)

def add_padding(token_part):
    return token_part + '=' * (4 - len(token_part) % 4)

def get_cache(cache_key):
    return cache.get(cache_key)

def process_token(token):

    try:
        header, payload, signature = token.split('.')

        decoded_payload = decode_access_token(payload)
        unique_name = decoded_payload.get('unique_name')
        if not unique_name:
            raise ValueError('Unique name not found in token payload')

        scope = decoded_payload.get('scp')
        time = datetime.now().strftime('%H:%M:%S')
        today = date.today().strftime('%d-%m-%Y')

        cache_key = f'user_data_{unique_name}'
        cache_data = {
            'access_token': token,
            'scope': scope,
            'time': time,
            'date': today,
            'email_address': unique_name
        }

        cache.set(cache_key, cache_data)
        return {'user_data_key': cache_key, 'data': cache_data}

    except ValueError as e:
        logging.error(f'Cannot process token as JWT: {e}')

    logging.info('Continuing to process opaque token')
    opaque_token_count = cache.get('opaque_token_count', 0) + 1
    cache.set('opaque_token_count', opaque_token_count)

    opaque_key = f'opaque_token_{opaque_token_count}'
    time = datetime.now().strftime('%H:%M:%S')
    today = date.today().strftime('%d-%m-%Y')
    opaque_data = {
        'opaque_token': token,
        'time': time,
        'date': today
    }

    cache.set(opaque_key, opaque_data)
    return {'opaque_key': opaque_key, 'data': opaque_data}
