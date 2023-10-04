import logging
import socket
from threading import Thread, Lock
from lib.commands import Command
from lib.constants import BUFFER_SIZE, DATA_SIZE, LOCAL_HOST, WRITE_MODE
from lib.constants import MAX_TIMEOUT_RETRIES, TIMEOUT, WINDOW_RECEIVER_SIZE
from lib.constants import LOCAL_PORT, READ_MODE, SELECTIVE_REPEAT
from lib.constants import MAX_WINDOW_SIZE, MAX_ACK_RESEND_TRIES
from lib.exceptions import WindowFullError
from lib.file_controller import FileController
from lib.flags import ACK, CLOSE, CLOSE_ACK, NO_FLAGS
from lib.message_utils import receive_msg, send_ack, send_close
from lib.log import log_received_msg, log_sent_msg
from lib.message import Message
from queue import Queue, Empty


class SelectiveRepeatProtocol:
    def __init__(self, socket):
        self.socket = socket
        self.seq_num = 0
        self.name = SELECTIVE_REPEAT
        self.send_base = 0  # it is the first packet in the window == its sqn
        self.rcv_base = 0
        self.window_size = WINDOW_RECEIVER_SIZE
        self.buffer = []
        self.not_acknowledged = 0  # n° packets sent but not acknowledged yet
        self.not_acknowledged_lock = Lock()
        self.acks_map = {}
        self.thread_pool = {}
        self.acks_received = 0

    # Receives acks in client from server
    def receive_acks(self, msq_queue, client_port, command,
                     server_address=None):
        continue_receiving = True
        tries = 0
        self.socket.settimeout(1.5)
        while continue_receiving:
            try:
                maybe_ack = self.socket.recvfrom(BUFFER_SIZE)[0]
                msg_received = Message.decode(maybe_ack)
                if msg_received.flags == ACK.encoded:
                    self.receive_ack_and_join_ack_thread(client_port,
                                                         msg_received)
                    continue_receiving = self.acks_received <= self.max_sqn
            except (socket.timeout, Empty):
                logging.error("Timeout on main thread ack")
                tries += 1
                if tries == MAX_ACK_RESEND_TRIES:
                    logging.error("Max tries reached for main ACK thread")
                    for thread in self.thread_pool.values():
                        thread.join()
                    continue_receiving = False
            except Exception as e:
                logging.error(f"Error receiving acks: {e}")
        logging.debug("Sending close msg")
        self.send_close_and_wait_ack(msq_queue, client_port, command,
                                     server_address=server_address)

    def receive_ack_and_join_ack_thread(self, client_port, msg_received):
        ack_number = msg_received.ack_number
        logging.debug(f"Received ACK: {ack_number}")
        self.join_ack_thread(msg_received)
        self.modify_not_acknowledged(-1)
        self.acks_received += 1

        if msg_received.command == Command.DOWNLOAD:
            log_received_msg(msg_received, client_port)
        if self.is_base_ack(ack_number):
            print("Moving send window."
                  + f"Current send base: {self.send_base}")
            self.move_send_window()
        else:
            logging.debug(f"Received messy ACK: {ack_number}")
            self.buffer.append(msg_received)

    def send_close_and_wait_ack(self, msq_queue, client_port, command,
                                server_address=None):
        close_tries = 0
        while close_tries < MAX_TIMEOUT_RETRIES:
            try:
                if server_address:
                    send_close(self.socket, command, server_address)
                else:
                    send_close(self.socket, command,
                               (LOCAL_HOST, client_port))
                maybe_close_ack = receive_msg(msq_queue, self.socket, 1.5)
                if Message.decode(maybe_close_ack).flags == CLOSE_ACK.encoded:
                    logging.debug("Received close ACK")
                break
            except (socket.timeout, Empty):
                close_tries += 1

    def is_base_ack(self, ack_number):
        return ack_number == self.send_base

    def join_ack_thread(self, msg_received):
        thread_is_alive = False
        while not thread_is_alive:
            try:
                ack_num = msg_received.ack_number
                self.acks_map[ack_num].put(ack_num)
                thread_is_alive = True
                logging.debug("Joining thread: %s", ack_num)
                self.thread_pool[ack_num].join()
                if self.thread_pool[ack_num].is_alive():
                    logging.debug("Failed to join thread")

                del self.acks_map[ack_num]
                del self.thread_pool[ack_num]
            except KeyError:
                continue

    def receive(self, decoded_msg, port, file_controller, server_address=None):
        logging.debug(f"Waiting for ack {self.rcv_base}")
        if decoded_msg.seq_number == self.rcv_base:
            self.process_expected_packet(decoded_msg, port, file_controller,
                                         server_address=server_address)
        elif self.packet_is_within_window(decoded_msg):
            self.buffer_packet(decoded_msg, port,
                               server_address=server_address)
        elif self.already_acknowledged(decoded_msg):
            # client lost ack, send ack again
            self.send_duplicated_ack(decoded_msg, port,
                                     server_address=server_address)
        else:
            # otherwise it is not within the window and it is discarded
            logging.error(f"Window starts at {self.rcv_base}"
                          + f" & ends at {self.rcv_base + self.window_size-1}")
            logging.error(f"Msg out of window: {decoded_msg.seq_number}")

    def process_expected_packet(self, decoded_msg, port, file_controller,
                                server_address=None):
        logging.debug("Received expected sqn")
        self.write_to_file(file_controller, decoded_msg)
        log_received_msg(decoded_msg, port)
        self.process_buffer(file_controller)
        seq_num = decoded_msg.seq_number
        logging.debug(f"Sending ACK: {seq_num}")
        if server_address:
            send_ack(decoded_msg.command, server_address[1],
                     seq_num, self.socket)
        else:
            send_ack(decoded_msg.command, port, seq_num, self.socket)
        self.seq_num += 1

    def already_acknowledged(self, decoded_msg):
        return decoded_msg.seq_number < self.rcv_base

    def send_duplicated_ack(self, decoded_msg, port, server_address=None):
        seq_num = decoded_msg.seq_number
        logging.debug(f"Message was already acked: {seq_num}")
        if server_address:
            send_ack(decoded_msg.command, server_address[1],
                     seq_num, self.socket)
        else:
            send_ack(decoded_msg.command, port, seq_num, self.socket)

    def buffer_packet(self, decoded_msg, port, server_address=None):
        log_received_msg(decoded_msg, port)
        seq_num = decoded_msg.seq_number
        logging.debug(f"Received msg: {seq_num}")
        if self.ack_is_not_repeated(decoded_msg):
            self.buffer.append(decoded_msg)
        logging.debug(f"Sending ACK: {seq_num}")
        if server_address:
            send_ack(decoded_msg.command, server_address[1],
                     seq_num, self.socket)
        else:
            send_ack(decoded_msg.command, port, seq_num, self.socket)

    def ack_is_not_repeated(self, decoded_msg):
        unique_sqns = [x.seq_number for x in self.buffer]
        logging.debug(f"Buffered seq nums {unique_sqns}")
        return decoded_msg.seq_number not in unique_sqns

    def process_buffer(self, file_controller):
        """
        Write to file those buffered packets that are after
        rcv_base and before a "jump" (another loss) in their sqn.
        """
        self.buffer.sort(key=lambda x: x.seq_number)
        next_base = self.rcv_base + 1
        remaining_buffer = []

        for packet in self.buffer:
            if packet.seq_number == next_base:
                self.write_to_file(file_controller, packet)
                next_base += 1
            else:
                remaining_buffer.append(packet)

        self.buffer = remaining_buffer
        self.move_rcv_window(min(next_base - self.rcv_base,
                                 WINDOW_RECEIVER_SIZE))

    def write_to_file(self, file_controller, packet):
        logging.debug(f"Writing to file sqn: {packet.seq_number}")
        file_controller.write_file(packet.data)

    def packet_is_within_window(self, decoded_msg):
        max_w_size = self.window_size - 1
        is_before_max = decoded_msg.seq_number <= self.rcv_base + max_w_size
        is_after_base = decoded_msg.seq_number > self.rcv_base
        return is_after_base and is_before_max

    def send(self, command, port, data, file_controller, server_address=None):
        if self.window_is_not_full():
            msg = Message(
                command,
                NO_FLAGS,
                len(data),
                file_controller.file_name,
                data,
                self.seq_num,
                0,
            )
            if server_address:
                self.socket.sendto(msg.encode(), server_address)
            else:
                self.socket.sendto(msg.encode(), (LOCAL_HOST, port))
            self.spawn_packet_ack_thread(port, msg,
                                         server_address=server_address)
            log_sent_msg(msg, self.seq_num, file_controller.get_file_size())
            self.seq_num += 1
            self.modify_not_acknowledged(1)
        else:
            raise WindowFullError

        if command == Command.UPLOAD:
            log_sent_msg(msg, self.seq_num, file_controller.get_file_size())

    def window_is_not_full(self):
        return self.not_acknowledged < self.window_size

    def spawn_packet_ack_thread(self, port, msg, server_address=None):
        ack_queue = Queue()
        self.acks_map[self.seq_num] = ack_queue
        args = (self.seq_num, ack_queue, msg.encode(), port, server_address)
        wait_ack_thread = Thread(target=self.wait_for_ack, args=args)
        wait_ack_thread.start()
        self.thread_pool[self.seq_num] = wait_ack_thread

    def modify_not_acknowledged(self, amount):
        self.not_acknowledged_lock.acquire()
        if (amount < 0 and self.not_acknowledged > 0) or amount > 0:
            self.not_acknowledged += amount
        self.not_acknowledged_lock.release()

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
        file_size = f_controller.get_file_size()
        self.set_window_size(int(file_size / DATA_SIZE))
        data = f_controller.read()
        ack_thread = Thread(target=self.receive_acks,
                            args=(msg_queue, client_port, command,
                                  server_address))
        ack_thread.start()

        while file_size > 0:
            data_length = len(data)
            try:
                self.send(command, client_port, data, f_controller,
                          server_address=server_address)
            except WindowFullError:
                continue
            data = f_controller.read()
            file_size -= data_length

        ack_thread.join(timeout=10)
        f_controller.close()

    def move_rcv_window(self, shift):
        self.rcv_base += min(shift, WINDOW_RECEIVER_SIZE)

    def move_send_window(self):
        self.buffer.sort()
        next_base = self.send_base + 1
        remaining_buffer = []

        for ack in self.buffer:
            if ack == next_base:
                next_base += 1
            else:
                remaining_buffer.append(ack)

        self.buffer = remaining_buffer
        self.send_base += min((next_base - self.send_base), self.window_size)

    def set_window_size(self, number_of_packets):
        self.window_size = self.calculate_window_size(number_of_packets)
        self.max_sqn = number_of_packets
        logging.debug(f"Window size: {self.window_size}")

    def calculate_window_size(self, number_of_packets):
        return min(int(number_of_packets / 2), MAX_WINDOW_SIZE)

    def wait_for_ack(self, ack_number, ack_queue, encoded_msg, port,
                     server_address=None):
        logging.info(f"Wating for ack {ack_number}")
        succesfully_acked = False
        tries = 1
        while not succesfully_acked:
            try:
                ack_queue.get(block=True, timeout=TIMEOUT)
                logging.debug(f"[THREAD for ACK {ack_number}]" +
                              "succesfully acked")
                succesfully_acked = True
            except Empty:
                if tries == MAX_ACK_RESEND_TRIES:
                    logging.error(f"Max tries reached for ACK {ack_number}")
                    break
                else:
                    logging.error(f"Timeout for ACK {ack_number}")
                    msg = Message.decode(encoded_msg)
                    try:
                        logging.debug(f"Sending msg back to server: {msg}")
                        if server_address:
                            self.socket.sendto(encoded_msg, server_address)
                        else:
                            self.socket.sendto(encoded_msg, (LOCAL_HOST, port))
                    except Exception as e:
                        logging.error(f"Error sending msg back to server: {e}")
                    tries += 1

    def receive_file(self, first_encoded_msg,
                     file_path, client_port=LOCAL_PORT,
                     server_address=None):
        f_controller = FileController.from_file_name(file_path, WRITE_MODE)
        # para cuando se desconecta un cliente repentinamente:
        self.socket.settimeout(5)
        encoded_messge = first_encoded_msg
        decoded_message = Message.decode(encoded_messge)
        while decoded_message.flags != CLOSE.encoded:
            self.receive(decoded_message, client_port, f_controller,
                         server_address=server_address)

            encoded_messge = self.socket.recvfrom(BUFFER_SIZE)[0]
            decoded_message = Message.decode(encoded_messge)

        if server_address:
            self.socket.sendto(Message.close_ack_msg(decoded_message.command),
                               server_address)
        else:
            self.socket.sendto(Message.close_ack_msg(decoded_message.command),
                               (LOCAL_HOST, client_port))
        f_controller.close()
