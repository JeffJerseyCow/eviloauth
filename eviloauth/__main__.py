import argparse
import importlib
import logging
import sys
import threading

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from werkzeug.serving import make_server

from . import MODULES, app, cache


def load_modules():
    module_dict = {}

    for module in [f'eviloauth.module.{k}.{i}' for (k, v) in MODULES['module'].items() for i in v]:
        module_dict[module] = importlib.import_module(module)
        module_dict[module].__load__()

    return module_dict


def set_log_level(verbose):
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    if verbose == 0:
        logging.basicConfig(level=logging.WARNING, format=log_format)
    elif verbose == 1:
        logging.basicConfig(level=logging.INFO, format=log_format)
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format=log_format)


def shutdown(flask_server):
    print('Exiting...')
    flask_server.shutdown()
    sys.exit()


def build_parser():
    parser = argparse.ArgumentParser(prog=f'eviloauth')
    parser.add_argument('-c', '--client-id', required=True,
                        help='OAuth2.0 Client ID')
    parser.add_argument('-r', '--response-type', default='token',
                        help='OAuth 2.0 Response Type [code (AuthZ "Code" Flow) | token (Implicit "Token" Flow)]')
    parser.add_argument('-s', '--scope', required=True, help='OAuth2.0 Scopes')
    parser.add_argument('-e', '--endpoint', required=True,
                        help='OAuth2.0 Target URI Endpoint')
    parser.add_argument('-f', '--final-destination', default='/', help='Final Destination location to redirect ' +
                        'user')
    parser.add_argument('-v', '--verbose', action='count',
                        default=0, help='Increase verbosity level')
    parser.add_argument('-u', '--redirect-uri-endpoint',
                        required=True, help='Redirect URI Endpoint string')
    parser.add_argument(
        '--redirect_server', default='127.0.0.1:5000', help='URI of the redirect server')
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    redirect_uri = f'https://{args.redirect_server}/{args.redirect_uri_endpoint}'

    set_log_level(args.verbose)

    logging.info(f'Endpoint: {args.endpoint}')
    logging.info(f'Client ID: {args.client_id}')
    logging.info(f'Scope: {args.scope}')
    logging.info(f'Response Type: {args.response_type}')
    logging.info(f'Redirect URI: {redirect_uri}')
    logging.info(f'Final Destination: {args.final_destination}')
    logging.info(f'{args.endpoint}?client_id={args.client_id}&scope={args.scope}&'
                 f'response_type={args.response_type}&redirect_uri={redirect_uri}')

    # Store arguments for routes.py
    app.config['ENDPOINT'] = args.endpoint
    app.config['CLIENT_ID'] = args.client_id
    app.config['SCOPE'] = args.scope
    app.config['RESPONSE_TYPE'] = args.response_type
    app.config['REDIRECT_URI'] = redirect_uri
    app.config['FINAL_DESTINATION'] = args.final_destination
    app.config['REDIRECT_URI_ENDPOINT'] = args.redirect_uri_endpoint

    # Build flask application
    from . import routes
    flask_server = make_server(
        '127.0.0.1', 5000, app, ssl_context='adhoc')
    t = threading.Thread(target=flask_server.serve_forever)
    t.start()

    # Build prompt
    completer = NestedCompleter.from_nested_dict(MODULES)
    session = PromptSession('eviloauth# ', completer=completer)

    # Load modules
    module_dict = load_modules()

    # Main process loop
    try:

        while True:
            commands = session.prompt()
            cmd, sub, arg = (commands.lower().split(
                ' ') + [None, None, None])[:3]

            try:

                if cmd == 'exit':
                    shutdown(flask_server)

                elif cmd == 'module':
                    mod = module_dict[f'eviloauth.{cmd}.{sub}.{arg}']
                    mod.__run__(cache, 0)

                elif cmd == 'tokens':
                    print([v for v in cache])

            # Inner except
            except KeyError as e:
                logging.warning('Unknown module %s' % e)

    # Outer except
    except KeyboardInterrupt:
        shutdown(flask_server)


if __name__ == '__main__':
    main()
