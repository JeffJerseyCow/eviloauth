import sys
import logging
import argparse
import threading
from prompt_toolkit import PromptSession
from werkzeug.serving import make_server
from prompt_toolkit.completion import NestedCompleter
import eviloauth.routes
from eviloauth import COMMANDS, app, cache, load_modules
from eviloauth.idp import IDP
from eviloauth.dispatcher import Dispatcher
from eviloauth.exceptions import EviloauthCommandException, EviloauthModuleException


def set_log_level(verbose):
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    if verbose == 0:
        logging.basicConfig(level=logging.WARNING, format=log_format)
    elif verbose == 1:
        logging.basicConfig(level=logging.INFO, format=log_format)
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format=log_format)


def build_parser():
    parser = argparse.ArgumentParser(prog=f'eviloauth')
    parser.add_argument('-v', '--verbose', action='count',
                        default=0, help='Increase verbosity level')
    parser.add_argument('-s', '--redirect_server',
                        default='127.0.0.1:5000', help='URI of the redirect server')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    set_log_level(args.verbose)

    logging.info(f'Redirect Server: {args.redirect_server}')

    # Build flask application
    server, port = (args.redirect_server.split(':') + [None, None])[:2]
    port = 443 if port is None else int(port)
    # TODO: Permit non-self-signed certificates
    flask_server = make_server(server, port, app, ssl_context='adhoc')
    t = threading.Thread(target=flask_server.serve_forever)
    t.start()

    # Build prompt
    completer = NestedCompleter.from_nested_dict(COMMANDS)
    session = PromptSession('eviloauth# ', completer=completer)

    # Load modules
    module_dict = load_modules()

    # Main process loop
    try:

        while True:
            commands = session.prompt()

            try:
                dispatcher = Dispatcher(
                    flask_server, module_dict, cache, args.redirect_server)
                dispatcher.dispatch(commands)

            # Inner except
            except EviloauthCommandException as e:
                logging.error('%s' % e)

            except EviloauthModuleException as e:
                logging.error('%s' % e)

            # Raise when module is not found
            except KeyError as e:
                logging.warning('Unknown module %s' % e)

    # Outer except
    except KeyboardInterrupt:
        print('Exiting...')
        flask_server.shutdown()
        sys.exit()


if __name__ == '__main__':
    main()
