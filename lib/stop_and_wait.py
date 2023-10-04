import logging
from queue import Empty
import socket
from lib.commands import Command
from lib.file_controller import FileController
from lib.flags import CLOSE, NO_FLAGS
from lib.constants import BUFFER_SIZE, LOCAL_HOST, LOCAL_PORT, TIMEOUT
from lib.constants import MAX_TIMEOUT_RETRIES, WRITE_MODE
from lib.constants import READ_MODE, STOP_AND_WAIT
from lib.message import Message
from lib.exceptions import DuplicatedACKError, TimeoutsRetriesExceeded
from lib.message_utils import receive_msg, send_ack, send_close_and_wait_ack
from lib.log import log_received_msg, log_sent_msg


class StopAndWaitProtocol():
    def __init__(self, socket):
        self.socket = socket
        self.seq_num = 0
        self.ack_num = 1
        self.tries_send = 0
        self.name = STOP_AND_WAIT

    def receive(self, decoded_msg, port, file_controller,
                transfer_socket=None):
        logging.debug(
            f"Receiving: {decoded_msg}" +
            f"next message expected: {self.ack_num}")

        if self.ack_num > decoded_msg.seq_number + 1:
            log_received_msg(decoded_msg, port)
            if transfer_socket:
                ack_msg = Message.ack_msg(decoded_msg.command,
                                          decoded_msg.seq_number + 1)
                transfer_socket.sendto(ack_msg, (LOCAL_HOST, port))
            else:
                send_ack(decoded_msg.command, port, decoded_msg.seq_number + 1,
                         self.socket)
        else:
            file_controller.write_file(decoded_msg.data)
            log_received_msg(decoded_msg, port)
            if transfer_socket:
                ack_msg = Message.ack_msg(decoded_msg.command, self.ack_num)
                transfer_socket.sendto(ack_msg, (LOCAL_HOST, port))
            else:
                send_ack(decoded_msg.command, port, self.ack_num, self.socket)
            self.ack_num += 1

    def send(self, command, port, data, file_controller, msg_queue=None,
             server_address=None):
        if self.tries_send >= MAX_TIMEOUT_RETRIES:
            logging.error("Max timeout retries reached")
            raise TimeoutsRetriesExceeded
        self.tries_send += 1
        msg = Message(command, NO_FLAGS, len(data),
                      file_controller.file_name, data, self.seq_num, 0)
        if server_address:
            self.socket.sendto(msg.encode(), server_address)
        else:
            self.socket.sendto(msg.encode(), (LOCAL_HOST, port))

        log_sent_msg(msg, self.seq_num, file_controller.get_file_size())

        self.socket.settimeout(TIMEOUT)
        try:
            encoded_message = receive_msg(None, self.socket, TIMEOUT)
            if Message.decode(encoded_message).ack_number <= self.seq_num:
                logging.info(f"Client {port}: received duplicated ACK")
                raise DuplicatedACKError
            else:
                self.tries_send = 0
                self.seq_num += 1
        except (socket.timeout, Empty) as e:
            logging.error("Timeout receiving ACK message")
            raise e

    def send_file(self, args=None, msg_queue=None,
                  client_port=LOCAL_PORT, file_path=None, server_address=None):
        f_controller = None
        command = Command.UPLOAD
        if file_path:
            f_controller = FileController.from_file_name(file_path, READ_MODE)
            command = Command.DOWNLOAD
        else:
            f_controller = FileController.from_args(args.src,
                                                    args.name, READ_MODE)
        data = f_controller.read()
        file_size = f_controller.get_file_size()
        while file_size > 0:
            data_length = len(data)
            try:
                self.send(command, client_port, data, f_controller,
                          server_address=server_address)
            except DuplicatedACKError:
                continue
            except (socket.timeout, Empty):
                logging.error("Timeout! Retrying...")
                continue
            except TimeoutsRetriesExceeded:
                raise TimeoutsRetriesExceeded
            data = f_controller.read()
            file_size -= data_length

        send_close_and_wait_ack(socket_=self.socket,
                                msq_queue=msg_queue,
                                client_port=client_port,
                                command=Command.DOWNLOAD,
                                server_address=server_address)
        f_controller.close()

    def receive_file(self,
                     file_path, client_port=LOCAL_PORT,
                     first_encoded_msg=None, server_address=None):
        f_controller = FileController.from_file_name(file_path, WRITE_MODE)
        # por si se desconecta un cliente repentinamente:
        self.socket.settimeout(5)
        encoded_messge = None
        if first_encoded_msg:
            encoded_messge = first_encoded_msg
        else:
            encoded_messge = self.socket.recvfrom(BUFFER_SIZE)[0]
        decoded_message = Message.decode(encoded_messge)

        while decoded_message.flags != CLOSE.encoded:
            if server_address:
                self.receive(decoded_message, server_address[1], f_controller,
                             transfer_socket=self.socket)
            else:
                self.receive(decoded_message, client_port, f_controller,
                             transfer_socket=self.socket)

            encoded_messge = self.socket.recvfrom(BUFFER_SIZE)[0]
            decoded_message = Message.decode(encoded_messge)

        if server_address:
            self.socket.sendto(Message.close_ack_msg(decoded_message.command),
                               server_address)
        else:
            self.socket.sendto(Message.close_ack_msg(decoded_message.command),
                               (LOCAL_HOST, client_port))
        f_controller.close()
