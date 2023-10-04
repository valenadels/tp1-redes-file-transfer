import logging
import os
from lib.constants import DATA_SIZE
from lib.exceptions import FileOpenException, FileReadingError


class FileController():
    @classmethod
    def from_file_name(self, file_name, mode):
        file_controller = FileController()
        file_controller.file_name = file_name
        self.src = file_name
        try:
            file_controller.file = open(self.src, mode)
        except Exception as e:
            logging.error(f'Error opening file {self.src}, error: {e}')
            raise FileOpenException
        return file_controller

    @classmethod
    def from_args(self, src, name, mode):
        file_controller = FileController()
        self.src = src
        file_controller.file_name = name
        try:
            file_controller.file = open(self.src, mode)
        except Exception as e:
            logging.error(f'Error opening file {self.src}, error: {e}')
            raise FileOpenException
        return file_controller

    def read(self):
        try:
            data = self.file.read(DATA_SIZE)
            return data
        except Exception as e:
            logging.error(f'Error reading file: {e}')
            raise FileReadingError

    def write_file(self, text):
        self.file.write(text)

    def get_file_size(self):
        return os.path.getsize(self.src)

    def close(self):
        self.file.close()

    def delete(self):
        os.remove(self.src)
