import logging
import os
from queue import Queue
from lib.exceptions import TimeoutsRetriesExceeded
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from threading import Thread
from lib.constants import BUFFER_SIZE, TIMEOUT
from lib.constants import DEFAULT_FOLDER, ERROR_EXISTING_FILE
from lib.flags import HI, HI_ACK, LIST
from lib.commands import Command
from lib.message import Message
from lib.utils import get_file_name, select_protocol
from lib.message_utils import send_close, send_error
from threading import Lock


class Server:
    def __init__(self, ip, port, args):
        self.ip = ip
        self.port = port
        self.clients = {}
        self.protocols = {}
        self.protocols_lock = Lock()
        storage = args.storage
        self.storage = storage if storage is not None else DEFAULT_FOLDER

        if not os.path.isdir(self.storage):
            os.makedirs(self.storage, exist_ok=True)

    def start(self):
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind((self.ip, self.port))
        logging.info(f"Server {self.ip} is running on port {self.port}")
        try:
            self.handle_socket_messages()
        except Exception as e:
            logging.error(f"Error in server: {e}")
            raise e

    def handle_socket_messages(self):
        while True:
            encoded_message, client_address = self.socket.recvfrom(BUFFER_SIZE)
            client_port = client_address[1]
            try:
                client_msg_queue = self.clients[client_port]
                client_msg_queue.put(encoded_message)

            except KeyError:  # client not in clients
                client_msg_queue = Queue()
                client_msg_queue.put(encoded_message)
                self.clients[client_port] = client_msg_queue
                args = (encoded_message, client_address, client_msg_queue)
                try:
                    client = Thread(target=self.handle_client_message,
                                    args=args)
                    client.start()
                except Exception as e:
                    logging.error(f"Error in thread {e}")

    def handle_client_message(self, encoded_msg, client_address, msg_queue):
        try:
            encoded_msg = msg_queue.get(block=True, timeout=TIMEOUT)
            decoded_msg = Message.decode(encoded_msg)
            if decoded_msg.flags == HI.encoded:
                self.three_way_handshake(client_address, msg_queue,
                                         decoded_msg)
        except Exception as e:  # possible Empty exception
            logging.error(f"Error handling client message: {e}")
            raise e

    def three_way_handshake(self, client_address, msg_queue, decoded_msg):
        client_port = client_address[1]
        protocol_RDT = decoded_msg.data.decode()
        logging.debug(
            f"Client {client_port}: wants to connect, sending confirmation, "
            + f"message type: {decoded_msg.command}. Protocol: {protocol_RDT}"
        )

        transfer_socket = socket(AF_INET, SOCK_DGRAM)
        protocol = select_protocol(protocol_RDT)
        self.protocols_lock.acquire()
        self.protocols[client_port] = protocol(transfer_socket)
        self.protocols_lock.release()
        self.send_hi_ack(client_address, decoded_msg, transfer_socket)

        try:
            encoded_message = transfer_socket.recvfrom(BUFFER_SIZE)[0]
            decoded_msg = Message.decode(encoded_message)
            if decoded_msg.flags == HI_ACK.encoded:
                self.init_file_transfer_operation(
                    msg_queue, decoded_msg, client_address, transfer_socket
                )
            else:
                self.close_client_connection(client_address)
        except Exception as e:
            del self.clients[client_port]
            logging.error(f"Client {client_port}: {e}")
            logging.info(
                f"Client {client_port}: handshake timeout." +
                " Closing connection."
            )
            raise e

    def close_client_connection(self, client_address):
        client_port = client_address[1]
        del self.clients[client_port]
        self.protocols_lock.acquire()
        del self.protocols[client_port]
        self.protocols_lock.release()
        logging.info(f"Client {client_port}: closing connection...")

    def init_file_transfer_operation(
        self, client_msg_queue, decoded_msg, client_address, transfer_socket
    ):
        client_port = client_address[1]
        logging.info(
            f"Client {client_port}: is online, message type: "
            + f"{decoded_msg.command}"
        )
        self.clients[client_port] = client_msg_queue
        if decoded_msg.command == Command.DOWNLOAD:
            self.handle_download(client_address, client_msg_queue,
                                 transfer_socket)
        elif decoded_msg.command == Command.UPLOAD:
            self.handle_upload(client_address, client_msg_queue,
                               transfer_socket)
        else:
            logging.error(
                f"Client {client_port}: unknown command "
                + "closing connection"
            )
            self.close_client_connection(client_port)
            send_close(self.socket, decoded_msg.command, client_address)

    def send_hi_ack(self, client_address, decoded_msg, transfer_socket):
        hi_ack = Message.hi_ack_msg(decoded_msg.command)
        transfer_socket.sendto(hi_ack, client_address)

    def handle_download(self, client_address, msg_queue, transfer_socket):
        client_port = client_address[1]
        e_msg = transfer_socket.recvfrom(BUFFER_SIZE)[0]
        msg = Message.decode(e_msg)
        command = msg.command

        self.protocols_lock.acquire()
        protocol = self.protocols[client_port]
        self.protocols_lock.release()

        if msg.flags == LIST.encoded:
            self.send_file_list(client_address)
        else:
            file_path = os.path.join(self.storage, msg.file_name)
            if not os.path.exists(file_path):
                send_error(transfer_socket, command, client_port,
                           ERROR_EXISTING_FILE)
                logging.error(f"File {msg.file_name} doesn't exist, try again")
                return

            try:
                protocol.send_file(client_port=client_port,
                                   file_path=file_path)
                self.close_client_connection(client_address)
            except TimeoutsRetriesExceeded:
                logging.error("Timeouts retries exceeded")
                self.close_client_connection(client_address)

    def send_file_list(self, client_address):
        files = os.listdir(self.storage)
        print("Server available files:")
        print(files)
        self.close_client_connection(client_address)

    def handle_upload(self, client_address, client_msg_queue, transfer_socket):
        client_port = client_address[1]
        self.protocols_lock.acquire()
        protocol = self.protocols[client_port]
        self.protocols_lock.release()
        msg = transfer_socket.recvfrom(BUFFER_SIZE)[0]
        file_name = get_file_name(self.storage, Message.decode(msg).file_name)
        logging.info(f"Uploading file to: {file_name}")
        try:
            protocol.receive_file(first_encoded_msg=msg,
                                  client_port=client_port,
                                  file_path=file_name)
            logging.info(f"File {file_name} uploaded, closing connection")
        except timeout:
            logging.error("Timeout on client")
            self.close_client_connection(client_address)

    def dequeue_decoded_msg(self, client_msg_queue):
        encoded_msg = client_msg_queue.get(block=True)
        return Message.decode(encoded_msg)

    def dequeue_decoded_msg_download(self, client_msg_queue):
        encoded_msg = client_msg_queue.get(block=True, timeout=TIMEOUT)

        return Message.decode(encoded_msg)
