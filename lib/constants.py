BUFFER_SIZE = 4096
HEADER_SIZE = 414
DATA_SIZE = BUFFER_SIZE - HEADER_SIZE

TIMEOUT = 0.5
MAX_TIMEOUT_RETRIES = 10
MAX_ACK_RESEND_TRIES = 10

LOCAL_HOST = "127.0.0.1"
LOCAL_PORT = 8080

STOP_AND_WAIT = "sw"
SELECTIVE_REPEAT = "sr"

WRITE_MODE = "wb"
READ_MODE = "rb"
EMPTY_FILE = 0
EMPTY_DATA = b""

DEFAULT_FOLDER = 'saved-files'

ERROR_EXISTING_FILE = "File already exists"

WINDOW_RECEIVER_SIZE = 20
MAX_WINDOW_SIZE = 10

DOWNLOADS_DIR = "downloads"

MAX_FILE_SIZE = 1073741824  # 1 GB
