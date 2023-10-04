import logging
from lib.constants import DATA_SIZE

RED = "\033[91m"
WHITE = "\033[0m"
GREEN = "\033[92m"
BLUE = "\033[94m"

error_format = logging.Formatter(
    f"[%(asctime)s] - {RED}[%(levelname)s]{WHITE}- %(message)s"
)
info_format = logging.Formatter(
    f"[%(asctime)s] - {GREEN}[%(levelname)s]{WHITE}- %(message)s"
)
debug_format = logging.Formatter(
    f"[%(asctime)s] - {BLUE}[%(levelname)s]{WHITE}- %(message)s"
)


class RDTFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            return info_format.format(record)
        elif record.levelno == logging.DEBUG:
            return debug_format.format(record)
        else:
            return error_format.format(record)


stdout_handler = logging.StreamHandler()
stdout_handler.setFormatter(RDTFormatter())


def prepare_logging(args):
    def level_verbosity():
        if args.verbose:
            return logging.DEBUG
        elif args.quiet:
            return logging.ERROR
        else:
            return logging.INFO

    logging.basicConfig(level=level_verbosity(), handlers=[stdout_handler])


def log_received_msg(msg, port):
    logging.info(
        f"Client {port}: received {len(msg.data)}"
        + f" bytes, package number: {msg.seq_number}"
    )


def log_sent_msg(msg, seq_num, file_size=0):
    amount_msg = int(file_size/DATA_SIZE)
    if file_size > 0:
        logging.info(f"Uploading {msg.data_length} bytes..."
                     + f"{seq_num}/{amount_msg}")
    logging.debug(f"Sent {msg} msg with seq_number {seq_num}")
