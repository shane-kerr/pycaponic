"""
Open and read Pcap-NG files.

https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
"""
import struct


class PcapNGFileError(Exception):
    pass

# Section header block
#
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +---------------------------------------------------------------+
#  0 |                   Block Type = 0x0A0D0D0A                     |
#    +---------------------------------------------------------------+
#  4 |                      Block Total Length                       |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  8 |                      Byte-Order Magic                         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 12 |          Major Version        |         Minor Version         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 16 |                                                               |
#    |                          Section Length                       |
#    |                                                               |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 24 /                                                               /
#    /                      Options (variable)                       /
#    /                                                               /
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                      Block Total Length                       |
#    +---------------------------------------------------------------+


class PcapNGFile:
    def __init__(self, fp):
        self.file = fp

    def read_pkt(self):
        # We start off reading the section header block.
        #
        # This is a bit tricky since we don't know the byte order that
        # the length fields are in until after we read the byte-order
        # magic.
        buf = self.file.read(24)
        if len(buf) != 24:
            raise PcapNGFileError("section header block missing header")

        blk_type = buf[0:4]
        if blk_type != bytes([0x0A, 0x0D, 0x0D, 0x0A]):
            raise PcapNGFileError("section header block bad type")

        byte_order_magic = buf[8:12]
        check_byte_order, = struct.unpack("<I", byte_order_magic)
        if check_byte_order == 0x1A2B3C4D:
            byte_order = "<"
        else:
            check_byte_order, = struct.unpack(">I", byte_order_magic)
            if check_byte_order == 0x1A2B3C4D:
                byte_order = ">"
            else:
                err = "section header block bad byte order magic "
                raise PcapNGFileError(err)

        blk_total_len, = struct.unpack(byte_order+"I", buf[4:8])
        if blk_total_len < 28:
            raise PcapNGFileError("section header block too short")

        section_len, = struct.unpack(byte_order+"q", buf[16:24])

        # Now that we have a confirmed good total block length we can
        # read the rest of the section header block.
        buf = self.file.read(blk_total_len - 24)
        if len(buf) != (blk_total_len - 24):
            raise PcapNGFileError("section header block truncated")


if __name__ == '__main__':
    with open('delme.pcap', 'rb') as my_fp:
        pcapf = PcapNGFile(my_fp)
        pcapf.read_pkt()
