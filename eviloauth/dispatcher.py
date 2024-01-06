import sys
import logging
from eviloauth.idp import IDP
from eviloauth.exceptions import EviloauthCommandException


class Dispatcher:
    def __init__(self, flask_server, module_dict, cache, redirect_server):
        logging.debug('Initializing dispatcher')
        logging.debug(f'\tFlask server: {flask_server}')
        logging.debug(f'\tModule dict: {module_dict}')
        logging.debug(f'\tCache: {cache}')
        logging.debug(f'\tRedirect server: {redirect_server}')

        self.flask_server = flask_server
        self.module_dict = module_dict
        self.cache = cache
        self.redirect_server = redirect_server

    def dispatch(self, commands):
        cmd, sub, arg, *args = commands.split(' ') + [None, None, None]

        if cmd == 'exit':
            self.dispatch_exit()

        elif cmd == 'module':
            self.dispatch_module(cmd, sub, arg)

        elif cmd == 'tokens':
            self.dispatch_tokens(cmd, sub)

        elif cmd == 'configure':
            self.dispatch_configure(cmd, sub, arg)

        elif cmd == 'target':
            self.dispatch_target(cmd, sub, arg)

        else:
            raise EviloauthCommandException(
                'Unknown command %s' % cmd)

    def dispatch_exit(self):
        print('Exiting...')
        self.flask_server.shutdown()
        sys.exit()

    def dispatch_module(self, cmd, sub, arg):
        mod = self.module_dict[f'eviloauth.{cmd}.{sub}.{arg}']
        mod.__run__(self.cache.get('target'), 0)

    def dispatch_tokens(self, cmd, sub):
        access_tokens = self.cache.get('tokens')
        if sub == 'list':
            print([v for v in access_tokens.keys()])
        elif sub == 'add':
            logging.error('Not implemented yet')
        else:
            raise EviloauthCommandException(
                'Unknown "%s" command %s' % cmd, sub)

    def dispatch_configure(self, cmd, sub, arg):
        IDP(arg, self.redirect_server)

    def dispatch_target(self, cmd, sub, arg):
        target = self.cache.get('target')
        tokens = self.cache.get('tokens')

        if sub == 'list':
            print(f'Current Target: {target}')

        elif sub == 'set':
            if arg in tokens.keys():
                access_token = tokens[arg]
                self.cache.set('target', access_token)

            elif arg not in tokens.keys():
                raise EviloauthCommandException(
                    'Unknown token %s' % arg)
