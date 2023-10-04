import sys
from lib.log import prepare_logging
from lib.constants import LOCAL_HOST, LOCAL_PORT
from lib.server import Server
from lib.args_parser import parse_args_server

if __name__ == "__main__":
    try:
        args = parse_args_server()
        prepare_logging(args)
        server = Server(LOCAL_HOST, LOCAL_PORT, args)
        server.start()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
