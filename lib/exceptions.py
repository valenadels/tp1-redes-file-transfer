class ServerConnectionError(Exception):
    pass


class ClientConnectionError(Exception):
    def __str__(self):
        return "There has been an error connecting to the server"
    pass


class FileOpenException(Exception):
    def __str__(self):
        return "Error opening file"
    pass


class FileReadingError(Exception):
    def __str__(self):
        return "Error reading file"
    pass


class DuplicatedACKError(Exception):
    def __str__(self):
        return "Duplicated ACK"
    pass


class WindowFullError(Exception):
    pass


class TimeoutsRetriesExceeded(Exception):
    def __str__(self):
        return "Timeouts retries exceeded"
    pass
