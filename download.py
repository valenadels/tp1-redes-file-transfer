import socket
from lib.commands import Command
from lib.constants import DOWNLOADS_DIR, MAX_TIMEOUT_RETRIES
from lib.exceptions import ServerConnectionError
from lib.message import Message
from lib.log import prepare_logging
from lib.client import Client
from lib.args_parser import parse_args_download
from lib.flags import ERROR, LIST
import sys
import logging
import os
from lib.message_utils import send_close
from lib.utils import get_file_name


def download(client, args):
    if args.files:
        print("Server will show files...")
        show_server_files(client)
        sys.exit(0)

    try:
        if not os.path.isdir(DOWNLOADS_DIR):
            os.makedirs(DOWNLOADS_DIR, exist_ok=True)

        download_using_protocol(client, args)
    except ServerConnectionError:
        logging.error("Server is offline")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


def show_server_files(client):
    msg_to_send = Message(Command.DOWNLOAD, LIST, 0, "", b"")
    client.send(msg_to_send.encode())
    msg_to_send = Message(Command.DOWNLOAD, LIST, 0, "", b"")
    client.send(msg_to_send.encode(), client.server_address)


def download_using_protocol(client, args):
    msg_to_send = Message.download_msg(args.name)

    encoded_messge = None
    retries = 0
    while retries < MAX_TIMEOUT_RETRIES:
        try:
            client.send(msg_to_send, client.server_address)
            encoded_messge, sa = client.receive()
            break
        except socket.timeout:
            logging.error("Download timeout! Retrying...")
            retries += 1
    if retries == MAX_TIMEOUT_RETRIES:
        logging.error("Connection error: "
                      + "HI_ACK or first DOWNLOAD not received")
        raise ServerConnectionError

    decoded_msg = Message.decode(encoded_messge)
    if decoded_msg.flags == ERROR.encoded:
        logging.error(decoded_msg.data)
        sys.exit(1)

    file_name = get_file_name(DOWNLOADS_DIR, args.dst)
    client.protocol.receive_file(first_encoded_msg=encoded_messge,
                                 file_path=file_name,
                                 server_address=client.server_address)
    logging.info("Download finished")


if __name__ == "__main__":
    try:
        args = parse_args_download()
        prepare_logging(args)
        client = Client(args.host, args.port, args.RDTprotocol)
        client.start(Command.DOWNLOAD, lambda: download(client, args))
    except KeyboardInterrupt:
        logging.info("\nExiting...")
        send_close(client.socket, Command.DOWNLOAD, (args.host, args.port))
        sys.exit(0)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)
