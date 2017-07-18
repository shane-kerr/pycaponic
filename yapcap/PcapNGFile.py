"""
Open and read Pcap-NG files.

https://pcapng.github.io/pcapng/

https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

TODO: skip parsing options if not needed
TODO: a more liberal mode for parsing
"""
import collections
import ipaddress
import struct


class PcapNGFileError(Exception):
    pass


# block types
BLK_TYPE_SHB = 0x0A0D0D0A
BLK_TYPE_IF = 0x00000001


# generic option identifiers
OPT_ENDOFOPT = 0
OPT_COMMENT = 1
# TODO: add custom types


# option identifiers for section header block
SHB_HARDWARE = 2
SHB_OS = 3
SHB_USERAPPL = 4


# option identifiers for the interface description block
IF_NAME = 2
IF_DESCRIPTION = 3
IF_IPv4ADDR = 4
IF_IPv6ADDR = 5
IF_MACADDR = 6
IF_EUIADDR = 7
IF_SPEED = 8
IF_TSRESOL = 9
IF_TZONE = 10
IF_FILTER = 11
IF_OS = 12
IF_FCSLEN = 13
IF_TSOFFSET = 14


def opt_str(buf, _):
    """
    Convert to a string type.
    """
    # decode assuming we are a UTF-8 string
    try:
        opt_val = buf.decode()
    except UnicodeDecodeError:
        raise PcapNGFileError("invalid UTF-8 string")
    # remove anything after NUL-termination
    nul_pos = opt_val.find("\0")
    if nul_pos >= 0:
        opt_val = opt_val[:nul_pos]
    # return our string
    return opt_val


def opt_ipv4(buf, _):
    """
    Convert to an IPv4Network type.
    """
    # make a mask that our IPv4Network constructor can take
    mask = '.'.join(str(b) for b in buf[4:8])
    try:
        opt_val = ipaddress.IPv4Network((buf[0:4], mask))
    except ValueError:
        raise PcapNGFileError("invalid network mask for IPv4 network")
    return opt_val


def opt_ipv6(buf, _):
    """
    Convert to an IPv6Network type.
    """
    try:
        opt_val = ipaddress.IPv6Network((buf[0:16], buf[16]))
    except ValueError:
        raise PcapNGFileError("invalid network mask for IPv6 network")
    return opt_val


def opt_uint64(buf, byte_order):
    """
    Convert to an unsigned 64-bit integer.
    """
    opt_val, = struct.unpack(byte_order+"I", buf)
    return opt_val


def opt_tsresol(buf, _):
    """
    Figure out the time resolution, as a fraction of a second.

    The value returned is the inverse of the resolution, so 1000 means
    1/1000 second resolution, which is 0.001 seconds or 1 millisecond.
    """
    tsresol = buf[0]
    if tsresol & 0x80:
        opt_val = 2 ** (tsresol & 0x7F)
    else:
        opt_val = 10 ** tsresol
    return opt_val


FilterInfo = collections.namedtuple('FilterInfo', ['code', 'info'])


def opt_filter(buf, _):
    """
    Extract the filter information, returned as a FilterInfo named tuple.
    """
    if len(buf) < 1:
        raise PcapNGFileError("if_filter must be at least 1 byte")
    return FilterInfo(code=buf[0], info=buf[1:])


# Tuple containing directives to check options
OptionCheck = collections.namedtuple('OptionCheck', [
    # name of the option (for printing)
    'opt_name',
    # length of the option, or None for any length
    'opt_len',
    # maximum occurrences, or None if any amount
    'opt_max_occur',
    # function to type convert & check the option, or None if leave as bytes
    'opt_fn',
])

OPTION_CHECKS_OPT = {
    OPT_ENDOFOPT: OptionCheck(opt_name='opt_endofopt',
                              opt_len=0, opt_max_occur=1, opt_fn=None),
    OPT_COMMENT: OptionCheck(opt_name='opt_comment',
                             opt_len=None, opt_max_occur=1, opt_fn=opt_str),
}

OPTION_CHECKS_SHB = {
    SHB_HARDWARE: OptionCheck(opt_name='shb_hardware',
                              opt_len=None, opt_max_occur=1, opt_fn=opt_str),
    SHB_OS: OptionCheck(opt_name='shb_os',
                        opt_len=None, opt_max_occur=1, opt_fn=opt_str),
    SHB_USERAPPL: OptionCheck(opt_name='shb_userappl',
                              opt_len=None, opt_max_occur=1, opt_fn=opt_str),
}

OPTION_CHECKS_IF = {
    IF_NAME: OptionCheck(opt_name='if_name',
                         opt_len=None, opt_max_occur=1, opt_fn=opt_str),
    IF_DESCRIPTION: OptionCheck(opt_name='if_description',
                                opt_len=None, opt_max_occur=1, opt_fn=opt_str),
    IF_IPv4ADDR: OptionCheck(opt_name='if_IPv4addr',
                             opt_len=8, opt_max_occur=None, opt_fn=opt_ipv4),
    IF_IPv6ADDR: OptionCheck(opt_name='if_IPv6addr',
                             opt_len=17, opt_max_occur=None, opt_fn=opt_ipv6),
    IF_MACADDR: OptionCheck(opt_name='if_MACaddr',
                            opt_len=6, opt_max_occur=1, opt_fn=None),
    IF_EUIADDR: OptionCheck(opt_name='if_EUIaddr',
                            opt_len=8, opt_max_occur=1, opt_fn=None),
    IF_SPEED: OptionCheck(opt_name='if_speed',
                          opt_len=8, opt_max_occur=1, opt_fn=opt_uint64),
    IF_TSRESOL: OptionCheck(opt_name='if_tsresol',
                            opt_len=1, opt_max_occur=1, opt_fn=opt_tsresol),
    IF_TZONE: OptionCheck(opt_name='if_tzone',
                          opt_len=4, opt_max_occur=1, opt_fn=None),
    IF_FILTER: OptionCheck(opt_name='if_filter',
                           opt_len=None, opt_max_occur=1, opt_fn=opt_filter),
    IF_OS: OptionCheck(opt_name='if_os',
                       opt_len=None, opt_max_occur=1, opt_fn=opt_str),
    IF_FCSLEN: OptionCheck(opt_name='if_fcslen',
                           opt_len=1, opt_max_occur=1, opt_fn=None),
    IF_TSOFFSET: OptionCheck(opt_name='if_tsoffset',
                             opt_len=8, opt_max_occur=1, opt_fn=opt_uint64),
}


class PcapNGFile:
    def __init__(self, fp):
        self.file = fp
        self.byte_order = None

    def _parse_options(self, opt_buf, checks):
        options = {}

        # If there is no option buffer (it is optional, after all), done.
        if not opt_buf:
            return options

        # Otherwise go through and get each option.
        while opt_buf:
            # verify we have option code & length at least
            if len(opt_buf) < 4:
                raise PcapNGFileError("option too short")

            # pull out the option code & length
            opt_code, opt_len = struct.unpack(self.byte_order+"HH",
                                              opt_buf[:4])

            # verify that we actually have the data claimed by the length
            if len(opt_buf) < (4 + opt_len):
                raise PcapNGFileError("option truncated")

            # get any checks we have (will be None if code unrecognized)
            check = checks.get(opt_code) or OPTION_CHECKS_OPT.get(opt_code)
            if check:
                opt_name = check.opt_name
            else:
                # XXX: if we had a warning mechanism we could warn here
                opt_name = str(opt_code)

            # validate the length is correct for this type
            if check and ((check.opt_len is not None) and
                          (opt_len != check.opt_len)):
                msg = ("option %s has length %d, should be %d" %
                       (check.opt_name, opt_len, check.opt_len))
                raise PcapNGFileError(msg)

            # get the actual contents of the option, and update our buffer
            opt_val_bytes = opt_buf[4:4+opt_len]
            padded_opt_len = opt_len + ((4 - (opt_len % 4)) % 4)
            opt_buf = opt_buf[4+padded_opt_len:]

            # if we have our end option, we are done
            if opt_code == OPT_ENDOFOPT:
                break

            # get existing option value, if any
            new_option = options.get(opt_name, [])

            # check to make sure multiple options are verified
            if check and (check.opt_max_occur is not None):
                if len(new_option) >= check.opt_max_occur:
                    errmsg = ("option %s appears too many times" %
                              check.opt_name)
                    raise PcapNGFileError(errmsg)

            # get the value of the option
            if check and check.opt_fn:
                opt_val = check.opt_fn(opt_val_bytes, self.byte_order)
            else:
                opt_val = opt_val_bytes

            # save our value (add to list if multiple possible)
            if check and (check.opt_max_occur == 1):
                options[opt_name] = opt_val
            else:
                new_option.append(opt_val)
                options[opt_name] = new_option

        # Check for a couple of error conditions after parsing the options.
        if opt_buf:
            raise PcapNGFileError("extra data in option section")

        # We used to test to make sure that we had an opt_endofopt option,
        # but this is not present in every block generated by tshark.

        # Finally, return our parsed options.
        return options

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
    #
    # TODO: refactor to separate reading & parsing
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
            self.byte_order = "<"
        else:
            check_byte_order, = struct.unpack(">I", byte_order_magic)
            if check_byte_order == 0x1A2B3C4D:
                self.byte_order = ">"
            else:
                err = "section header block bad byte order magic "
                raise PcapNGFileError(err)

        # Get the total block length.
        blk_total_len, = struct.unpack(self.byte_order+"I", buf[4:8])
        if blk_total_len < 28:
            raise PcapNGFileError("section header block too short")
        if (blk_total_len % 4) != 0:
            msg = "section header block length not multiple of 4"
            raise PcapNGFileError(msg)

        # Check out version.
        ver_maj, ver_min = struct.unpack(self.byte_order+"HH", buf[12:16])
        if (ver_maj != 1) or (ver_min != 0):
            raise PcapNGFileError("Pcap NG format unsupported")

        # Grab our section length (-1 means "unspecified")
        section_len, = struct.unpack(self.byte_order+"q", buf[16:24])

        # Now that we have a confirmed good total block length we can
        # read the rest of the section header block.
        buf = self.file.read(blk_total_len - 24)
        if len(buf) != (blk_total_len - 24):
            raise PcapNGFileError("section header block truncated")

        # Look at the end of the section header block and check that the
        # total block length is replicated.
        blk_total_len_check, = struct.unpack(self.byte_order+"I", buf[-4:])
        if blk_total_len != blk_total_len_check:
            raise PcapNGFileError("section header block length not duplicated")

        # Finally we parse the options
        options = self._parse_options(buf[:-4], OPTION_CHECKS_SHB)

        # Return what we found
        return options, section_len

    # Interface Description Block
    #
    #
    #     0                   1                   2                   3
    #     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #    +---------------------------------------------------------------+
    #  0 |                    Block Type = 0x00000001                    |
    #    +---------------------------------------------------------------+
    #  4 |                      Block Total Length                       |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  8 |           LinkType            |           Reserved            |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 12 |                            SnapLen                            |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 16 /                                                               /
    #    /                      Options (variable)                       /
    #    /                                                               /
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |                      Block Total Length                       |
    #    +---------------------------------------------------------------+
    def _parse_if_block(self, buf):
        """
        Parse the buffer without the block type and block total length
        values.
        """
        if len(buf) < 8:
            raise PcapNGFileError("interface description block too short")
        linktype, = struct.unpack(self.byte_order+"H", buf[:2])
        snaplen, = struct.unpack(self.byte_order+"I", buf[4:8])
        options = self._parse_options(buf[8:-4], OPTION_CHECKS_IF)
        return options, linktype, snaplen

    def _read_block(self):
        """
        Read a generic block.
        """
        # Read the block type and block length.
        buf = self.file.read(8)
        if len(buf) != 8:
            raise PcapNGFileError("block missing header")
        blk_type, blk_len = struct.unpack(self.byte_order+"II", buf)
        if (blk_len % 4) != 0:
            raise PcapNGFileError("block length not multiple of 4")

        # Read the rest of the block, based on block length.
        buf = self.file.read(blk_len - 8)
        if len(buf) != blk_len - 8:
            raise PcapNGFileError("block truncated")

        # Check the final block length value.
        blk_len_check, = struct.unpack(self.byte_order+"I", buf[-4:])
        if blk_len != blk_len_check:
            raise PcapNGFileError("block length not duplicated")

        # Return the block information
        return blk_type, buf[:-4]

    def read_pkt(self):
        # We start off reading the section header block.
        section_opt, section_len = self.read_section_header_block()
        print(section_opt)
        # Read next packet (which must be Interface Description Block)
        blk_type, buf = self._read_block()
        if_opt, if_linktype, if_snaplen = self._parse_if_block(buf)
        print(if_opt)


if __name__ == '__main__':
    with open('delme.pcap', 'rb') as my_fp:
        pcapf = PcapNGFile(my_fp)
        pcapf.read_pkt()
