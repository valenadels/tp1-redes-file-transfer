from argparse import ArgumentParser
from lib.constants import SELECTIVE_REPEAT, STOP_AND_WAIT


def parse_args_upload():
    parser = ArgumentParser(
        prog="upload",
        description="This is a program to upload files to a server")

    add_args(parser)

    parser.add_argument(
        "-s",
        "--src",
        help="source file path",
        action="store",
        required=True,
        type=str
    )

    parser.add_argument(
        "-pr",
        "--RDTprotocol",
        help="stop_and_wait (sw) or selective_repeat (sr)",
        action="store",
        type=str
    )

    return validate_args_upload(parser)


def parse_args_server():
    description = "This is a program to upload or download files from a server"
    parser = ArgumentParser(
        prog="server",
        description=description)

    add_args(parser)

    parser.add_argument(
        "-s",
        "--storage",
        help="storage dir path",
        action="store",
        required=False,
        type=str
    )

    return validate_args_server(parser)


def parse_args_download():
    parser = ArgumentParser(
        prog="download",
        description="This is a program to download files from a server")

    add_args(parser)

    parser.add_argument(
        "-d",
        "--dst",
        help="destination file path",
        action="store",
        required=False,
        type=str
    )

    parser.add_argument(
        "-pr",
        "--RDTprotocol",
        help="stop_and_wait (sw) or selective_repeat (sr)",
        action="store",
        type=str
    )

    parser.add_argument(
        "-f",
        "--files",
        help="show available files to download",
        action="store_true"
    )

    return validate_args_download(parser)


def add_args(parser):
    group_verbosity = parser.add_mutually_exclusive_group(required=False)

    group_verbosity.add_argument(
        "-v",
        "--verbose",
        help="increase output verbosity",
        action="store_true"
    )

    group_verbosity.add_argument(
        "-q",
        "--quiet",
        help="decrease output verbosity",
        action="store_true"
    )

    parser.add_argument(
        "-H",
        "--host",
        help="server IP address",
        action="store",
        type=str
    )

    parser.add_argument(
        "-p",
        "--port",
        help="server port",
        action="store",
        type=int
    )

    parser.add_argument(
        "-n",
        "--name",
        help="file name",
        action="store",
        type=str
    )


def validate_args_upload(parser):
    args = parser.parse_args()

    if args.verbose:
        print("verbosity turned on")
    if args.quiet:
        print("quiet turned on")
    if args.host is None:
        args.host = "localhost"
    if args.port is None:
        args.port = 8080
    if args.name is None:
        args.name = args.src.split("/")[-1]
    if args.RDTprotocol is None:
        args.RDTprotocol = STOP_AND_WAIT

    return args


def validate_args_download(parser):
    args = parser.parse_args()
    if not args.files and not args.dst:
        parser.error("Either -f/--files or -d/--dst is required.")
    if args.verbose:
        print("verbosity turned on")
    if args.quiet:
        print("quiet turned on")
    if args.host is None:
        args.host = "localhost"
    if args.port is None:
        args.port = 8080
    protocols = [STOP_AND_WAIT, SELECTIVE_REPEAT]
    if args.RDTprotocol is None or args.RDTprotocol not in protocols:
        args.RDTprotocol = STOP_AND_WAIT

    return args


def validate_args_server(parser):
    args = parser.parse_args()

    if args.verbose:
        print("verbosity turned on")
    if args.quiet:
        print("quiet turned on")
    if args.host is None:
        args.host = "localhost"
    if args.port is None:
        args.port = 8080

    return args
