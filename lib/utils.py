import os
from lib.constants import SELECTIVE_REPEAT
from lib.selective_repeat import SelectiveRepeatProtocol
from lib.stop_and_wait import StopAndWaitProtocol


def select_protocol(protocol):
    if protocol == SELECTIVE_REPEAT:
        return SelectiveRepeatProtocol
    else:
        return StopAndWaitProtocol


# Returns the file name with a sequential number
# appended to it if it already exists
def get_file_name(dir, file_name):
    i = 1
    file_name_base, extension = os.path.splitext(file_name)
    new_name = f"{dir}/{file_name_base}{extension}"

    while os.path.exists(new_name):
        new_name = f"{dir}/{file_name_base}_{i}{extension}"
        i += 1

    return new_name
