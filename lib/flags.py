class Flag:
    def __init__(self, id):
        self.encoded = id

    def __str__(self):
        flags_dict = {
            8: "HI",
            10: "HI_ACK",
            4: "CLOSE",
            3: "ERROR",
            6: "CLOSE_ACK",
            5: "LIST",
            2: "ACK",
            0: "NO_FLAGS"
        }
        return flags_dict.get(self.encoded, "UNKNOWN FLAG")

    def get_bytes(self):
        return self.encoded.to_bytes(1, byteorder='big')


CLOSE_ACK = Flag(6)
HI_ACK = Flag(10)
CLOSE = Flag(4)
HI = Flag(8)
ERROR = Flag(3)
ACK = Flag(2)
NO_FLAGS = Flag(0)
LIST = Flag(5)
