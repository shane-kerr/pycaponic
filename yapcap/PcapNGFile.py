"""
Open and read Pcap-NG files.

https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

TODO: skip parsing options if not needed?
TODO: a more liberal mode for parsing
"""
import struct


class PcapNGFileError(Exception):
    pass


# generic option identifiers
OPT_ENDOFOPT = 0
OPT_COMMENT = 1


# option identifiers for section header block
SHB_HARDWARE = 2
SHB_OS = 3
SHB_USERAPPL = 4

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

    def _parse_options(self, byte_order, opt_buf):
        options = {}

        # If there is no option buffer (it is optional, after all), done.
        if not opt_buf:
            return options

        # Otherwise go through and get each option.
        found_end = False
        while opt_buf:
            if len(opt_buf) < 4:
                raise PcapNGFileError("option too short")
            opt_code, opt_len = struct.unpack(byte_order+"HH", opt_buf[:4])
            if len(opt_buf) < (4 + opt_len):
                raise PcapNGFileError("option truncated")
            opt_val = opt_buf[4:4+opt_len]
            padded_opt_len = opt_len + ((4 - (opt_len % 4)) % 4)
            opt_buf = opt_buf[4+padded_opt_len:]
            if opt_code == OPT_ENDOFOPT:
                found_end = True
                break
            if opt_code in options:
                errmsg = "option %d appears twice in one block" % opt_code
                raise PcapNGFileError(errmsg)
            options[opt_code] = opt_val

        # Check for a couple of error conditions after parsing the options.
        if opt_buf:
            raise PcapNGFileError("extra data in option section")
        if not found_end:
            raise PcapNGFileError("missing end of option marker")

        # Finally, return our parsed options.
        return options

    def read_section_header_block(self):
        # This is a bit tricky since we don't know the byte order that
        # the length fields are in until after we read the byte-order
        # magic.

        # Read the required fixed length of the section header block.
        buf = self.file.read(24)
        if len(buf) != 24:
            raise PcapNGFileError("section header block missing header")

        # Verify that we start with the correct block type.
        blk_type = buf[0:4]
        if blk_type != bytes([0x0A, 0x0D, 0x0D, 0x0A]):
            raise PcapNGFileError("section header block bad type")

        # Figure out our byte ordering based on the byte order magic number.
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

        # Get the total block length.
        blk_total_len, = struct.unpack(byte_order+"I", buf[4:8])
        if blk_total_len < 28:
            raise PcapNGFileError("section header block too short")

        # Check out version.
        ver_maj, ver_min = struct.unpack(byte_order+"HH", buf[12:16])
        if (ver_maj != 1) or (ver_min != 0):
            raise PcapNGFileError("Pcap NG format unsupported")

        # Grab our section length (-1 means "unspecified")
        section_len, = struct.unpack(byte_order+"q", buf[16:24])

        # Now that we have a confirmed good total block length we can
        # read the rest of the section header block.
        buf = self.file.read(blk_total_len - 24)
        if len(buf) != (blk_total_len - 24):
            raise PcapNGFileError("section header block truncated")

        # Look at the end of the section header block and check that the
        # total block length is replicated.
        blk_total_len_check, = struct.unpack(byte_order+"I", buf[-4:])
        if blk_total_len != blk_total_len_check:
            raise PcapNGFileError("section header block length not duplicated")

        # Finally we parse the options
        options = self._parse_options(byte_order, buf[:len(buf)-4])

        # Return what we found
        return byte_order, section_len, options

    def read_pkt(self):
        # We start off reading the section header block.
        byte_order, section_len, section_opt = self.read_section_header_block()


if __name__ == '__main__':
    with open('delme.pcap', 'rb') as my_fp:
        pcapf = PcapNGFile(my_fp)
        pcapf.read_pkt()
