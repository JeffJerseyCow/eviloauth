import jwt
import logging
from datetime import datetime, timedelta
from enum import Enum


class TokenType(Enum):
    JAT = 1
    OAT = 2
    INVALID = 3


class TokenStatus(Enum):
    VALID = 1
    EXPIRED = 2
    NOT_APPLICABLE = 3


class ExpiryStatus(Enum):
    VALID = 1
    EXPIRED = 2
    NOT_APPLICABLE = 3


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
            self.token = jwt.decode(
                raw_token, options={'verify_signature': False})
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
                hours, remainder = divmod(remaining_time.total_seconds(), 3600)
                minutes, seconds = divmod(remainder, 60)
                formatted_time = f"{int(hours):02d}:{int(minutes):02d}:{
                    int(seconds):02d}"
                return formatted_time
            else:
                return ExpiryStatus.EXPIRED
        return ExpiryStatus.NOT_APPLICABLE

    def set_scope(self, scope):
        self.scp = scope

    def set_expiry(self, expiry_datetime):
        self.exp_datetime = expiry_datetime

    def get_token_type(self):
        if self.is_jwt:
            return TokenType.JAT
        elif self.token_id:
            return TokenType.OAT
        return TokenType.INVALID

    def __str__(self):
        token_type = self.get_token_type()
        if token_type == TokenType.JAT:
            return f'{TokenType.JAT.name}-{self.upn}'
        elif token_type == TokenType.OAT:
            return f'{TokenType.OAT.name}-{self.token_id}'
        else:
            return TokenType.INVALID.name

    def __repr__(self):
        return self.__str__()
