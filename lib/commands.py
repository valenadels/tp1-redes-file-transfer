from enum import Enum


class Command(Enum):
    DOWNLOAD = 1
    UPLOAD = 2

    def from_values(value):
        if value == 1:
            return Command.DOWNLOAD
        elif value == 2:
            return Command.UPLOAD
        else:
            raise ValueError

    def get_bytes(self):
        return self.value.to_bytes(1, byteorder='big', signed=False)
