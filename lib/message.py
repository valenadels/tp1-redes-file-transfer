import logging
from lib.flags import ACK, CLOSE, CLOSE_ACK, HI, HI_ACK, NO_FLAGS, ERROR, Flag
from lib.commands import Command
from lib.constants import BUFFER_SIZE, EMPTY_DATA, EMPTY_FILE


def add_padding(data: bytes, n: int):
    k = n - len(data)
    if k < 0:
        raise ValueError
    return data + b"\0" * k


"""
command: [DOWNLOAD, UPLOAD]
flags: [HI, CLOSE, ACK, CLOSE_ACK, HI_ACK, ERROR, NO_FLAGS, LIST]
file_length: [int]
file_path: [str]
file_name: [str]
id: [int]
data: [bytes]
ack_number: [int]
seq_number: [int]
"""


class Message:
    def __init__(self, command: Command, flags: Flag, data_length: int,
                 file_name: str, data: bytes, seq_number=0, ack_number=0):
        self.command = command
        self.flags = flags
        self.data_length = data_length
        self.file_name = file_name
        self.seq_number = seq_number
        self.ack_number = ack_number
        self.data = data

    def __str__(self):
        return (
            f"Message: "
            f"command={self.command}, "
            f"flags={self.flags}, "
            f"data_length={self.data_length}, "
            f"file_name={self.file_name}, "
            f"seq_number={self.seq_number}, "
            f"ack_number={self.ack_number}, "
        )

    @classmethod
    def decode(cls, bytes_arr: bytes):
        # Assuming 'command' is a single byte
        try:
            command = Command.from_values(bytes_arr[0])
        except ValueError:
            logging.error("Invalid command")
            raise ValueError("Invalid command")

        # Assuming 'flags' is 1 byte
        flags = bytes_arr[1]

        # Assuming 'file_length' is a 32-bit integer (4 bytes)
        f_data = int.from_bytes(bytes_arr[2:6], byteorder="big")

        # Assuming 'file_name' is a UTF-8 encoded string (up to 400 bytes)
        file_name_bytes = bytes_arr[6:406]
        f_name = file_name_bytes.decode().strip('\0')

        # Assuming 'seq_number' is a 32-bit integer (4 bytes)
        seq_n = int.from_bytes(bytes_arr[406:410], byteorder="big")

        # Assuming 'ack_number' is a 32-bit integer (4 bytes)
        ack_n = int.from_bytes(bytes_arr[410:414], byteorder="big")

        # Assuming 'data' is the remaining bytes after the previous fields
        data = bytes_arr[414: 414 + f_data]

        return Message(command, flags, f_data, f_name, data, seq_n, ack_n)

    def encode(self):
        bytes_arr = b""
        bytes_arr += self.command.get_bytes()
        bytes_arr += self.flags.get_bytes()
        bytes_arr += self.data_length.to_bytes(4,
                                               signed=False, byteorder='big')

        if self.file_name is not None:
            bytes_arr += add_padding(self.file_name.encode(), 400)

        bytes_arr += self.seq_number.to_bytes(4, signed=False, byteorder='big')
        bytes_arr += self.ack_number.to_bytes(4, signed=False, byteorder='big')

        # append data from position 1024 to 2048
        bytes_arr += add_padding(self.data, BUFFER_SIZE - len(bytes_arr))

        return bytes_arr

    @classmethod
    def ack_msg(cls, command, ack_num):
        msg = Message(command, ACK, EMPTY_FILE, "", EMPTY_DATA, 0, ack_num)
        return msg.encode()

    @classmethod
    def close_msg(cls, command):
        return Message(command, CLOSE, EMPTY_FILE, "", EMPTY_DATA).encode()

    @classmethod
    def hi_ack_msg(cls, command):
        return Message(command, HI_ACK, EMPTY_FILE, "", EMPTY_DATA).encode()

    @classmethod
    def hi_msg(cls, command, protocol):
        return Message(command, HI, len(protocol.name.encode()), "",
                       protocol.name.encode()).encode()

    @classmethod
    def download_msg(cls, file_name):
        msg = Message(Command.DOWNLOAD, NO_FLAGS, EMPTY_FILE,
                      file_name, EMPTY_DATA)
        return msg.encode()

    @classmethod
    def close_ack_msg(cls, command):
        return Message(command, CLOSE_ACK, EMPTY_FILE, "", EMPTY_DATA).encode()

    @classmethod
    def error_msg(cls, command, error_msg):
        msg = Message(command, ERROR, EMPTY_FILE, "", data=error_msg.encode())
        return msg.encode()
