import jwt
import logging
from datetime import datetime
class AccessToken:
    def __init__(self, raw_token):
        self.is_jwt = False
        self.token = None
        self.scp = None
        self.upn = None
        self.exp_datetime = None
        self.raw_token = raw_token
        self.token_id = raw_token[-10:]
        self.time = datetime.now().strftime('%H:%M:%S')
        self.today = datetime.today().strftime('%d-%m-%Y')

        try:
            self.token = jwt.decode(raw_token, options={'verify_signature': False})
            self.is_jwt = True
            self.upn = self.token.get('upn')
            self.scp = self.token.get('scp')
            self.exp = self.token.get('exp')
            if self.exp:
                self.exp_datetime = datetime.utcfromtimestamp(self.exp)
        except jwt.exceptions.DecodeError as e:
            logging.error(f'Cannot process token as JWT: {e}')

    def set_upn(self, upn):
        self.upn = upn

    def get_time_until_expiry(self):
        if self.exp_datetime:
            remaining_time = self.exp_datetime - datetime.utcnow()
            if remaining_time.total_seconds() > 0:
                return str(remaining_time).split('.')[0]  # Return as HH:MM:SS
            else:
                return "Expired"
        return "N/A"
    
    def set_scope(self, scope):
        self.scp = scope

    def set_expiry(self, expiry_datetime):
        self.exp_datetime = expiry_datetime

    def __str__(self):
        if self.is_jwt:

            return f'JWT-{self.upn}'
        
        else:
            return f'OAT-{self.token_id}'

    def __repr__(self):
        return self.__str__()