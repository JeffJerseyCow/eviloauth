import logging
from datetime import datetime

import jwt

class AccessToken:
    def __init__(self, raw_token):
        self.is_jwt = False
        self.token = None
        self.scp = None
        self.raw_token = raw_token
        self.token_id = raw_token[-10:]
        self.time = datetime.now().strftime('%H:%M:%S')
        self.today = datetime.today().strftime('%d-%m-%Y')

        try:
            self.token = jwt.decode(
                raw_token, options={'verify_signature': False})
            self.is_jwt = True
            self.upn = self.token.get('upn')
            self.scp = self.token.get('scp')
        except jwt.exceptions.DecodeError as e:
            logging.error(f'Cannot process token as JWT: {e}')

    def __str__(self):
        if self.is_jwt:
            return f'JWT-{self.upn}-{self.token_id}-{self.time}'
        else:
            return f'OAT-{self.token_id}-{self.time}'

    def __repr__(self):
        return self.__str__()
