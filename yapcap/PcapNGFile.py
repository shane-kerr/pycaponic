"""
Open and read Pcap-NG files.

https://pcapng.github.io/pcapng/

https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html

TODO: skip parsing options if not needed
TODO: a more liberal mode for parsing
"""
import collections
import decimal
import ipaddress
import math
import struct
import time


class PcapNGFileError(Exception):
    pass


# default time resolution
DEFAULT_TS_RESOL = decimal.Decimal(1000000)


# block types
BLK_TYPE_SHB = 0x0A0D0D0A
BLK_TYPE_IF = 0x00000001
BLK_TYPE_EPB = 0x00000006


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


# option identifiers for the enhanced packet block
EPB_FLAGS = 2
EPB_HASH = 3
EPB_DROPCOUNT = 4


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
    return decimal.Decimal(opt_val)


FilterInfo = collections.namedtuple('FilterInfo', ['code', 'info'])


def opt_filter(buf, _):
    """
    Extract the filter information, returned as a FilterInfo named tuple.
    """
    if len(buf) < 1:
        raise PcapNGFileError("if_filter must be at least 1 byte")
    return FilterInfo(code=buf[0], info=buf[1:])


EPB_Flags = collections.namedtuple('EPB_Flags',
                                   ['in_out_pkt',
                                    'reception',
                                    'fcs_len',
                                    'link_errors'])


def opt_epb_flags(buf, byte_order):
    """
    Decode the enhanced packet block flags.
    """
    opt_val, = struct.unpack(byte_order+"I", buf)

    in_out_pkt_val = opt_val & 0b11
    if in_out_pkt_val == 0:
        in_out_pkt = "information not available"
    elif in_out_pkt_val == 1:
        in_out_pkt = "inbound"
    elif in_out_pkt_val == 2:
        in_out_pkt = "outbound"
    else:
        raise PcapNGFileError("invalid I/O packet in EPB flags")

    reception_val = (opt_val >> 2) & 0b111
    if reception_val == 0:
        reception_type = "not specified"
    elif reception_val == 1:
        reception_type = "unicast"
    elif reception_val == 2:
        reception_type = "multicast"
    elif reception_val == 3:
        reception_type = "broadcast"
    elif reception_val == 4:
        reception_type = "promiscuous"
    else:
        raise PcapNGFileError("invalid reception type in EPB flags")

    fcs_len = (opt_val >> 5) & 0b1111
    if fcs_len == 0:
        fcs_len = None

    reserved = (opt_val >> 9) & 0b1111111
    if reserved != 0:
        raise PcapNGFileError("reserved bits set in EPB flags")

    errors = []
    if opt_val & 0b10000000000000000000000000000000:
        errors.append("symbol")
    if opt_val & 0b01000000000000000000000000000000:
        errors.append("preamble")
    if opt_val & 0b00100000000000000000000000000000:
        errors.append("start frame delimiter")
    if opt_val & 0b00010000000000000000000000000000:
        errors.append("unaligned frame")
    if opt_val & 0b00001000000000000000000000000000:
        errors.append("wrong inter-frame gap")
    if opt_val & 0b00000100000000000000000000000000:
        errors.append("packet too short")
    if opt_val & 0b00000010000000000000000000000000:
        errors.append("CRC")

    return EPB_Flags(in_out_pkt=in_out_pkt,
                     reception=reception_type,
                     fcs_len=fcs_len,
                     link_errors=errors)


HashInfo = collections.namedtuple('HashInfo', ['algorithm', 'value'])


def opt_epb_hash(buf, _):
    """
    Decode the enhanced packet block flags.
    """
    if len(buf) < 1:
        raise PcapNGFileError("epb_hash must be at least 1 byte")
    alg_code = buf[0]
    hash_val = buf[1:]
    if alg_code == 0:
        alg = "2s complement"
    elif alg_code == 1:
        alg = "XOR"
    elif alg_code == 2:
        if len(hash_val) != 4:
            raise PcapNGFileError("epb_hash CRC32 must be 4 bytes")
        alg = "CRC32"
    elif alg_code == 3:
        if len(hash_val) != 16:
            raise PcapNGFileError("epb_hash MD5 must be 16 bytes")
        alg = "MD5"
    elif alg_code == 4:
        if len(hash_val) != 20:
            raise PcapNGFileError("epb_hash SHA-1 must be 20 bytes")
        alg = "SHA-1"
    else:
        alg = str(alg_code)

    return HashInfo(algorithm=alg, value=hash_val)


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

OPTION_CHECKS_EPB = {
    EPB_FLAGS: OptionCheck(opt_name='epb_flags',
                           opt_len=4, opt_max_occur=1, opt_fn=opt_epb_flags),
    EPB_HASH: OptionCheck(opt_name='epb_hash',
                          opt_len=None, opt_max_occur=1, opt_fn=opt_epb_hash),
    EPB_DROPCOUNT: OptionCheck(opt_name='epb_dropcount',
                               opt_len=None,
                               opt_max_occur=1,
                               opt_fn=opt_uint64),
}

SectionHeaderBlock = collections.namedtuple('SectionHeaderBlock',
                                            ['section_len', 'options'])

InterfaceDescriptionBlock = collections.namedtuple('InterfaceDescriptionBlock',
                                                   ['linktype',
                                                    'snaplen',
                                                    'options', ])


class PcapNGFile:
    def __init__(self, fp):
        self.file = fp
        self.byte_order = ''

        # We start off reading the section header block.
        blk_type, buf = self._read_block()
        if blk_type != BLK_TYPE_SHB:
            raise PcapNGFileError("first block must be a Section Header Block")
        shb = self._parse_section_header_block(buf)

        # Set our various block information.
        self.shb = shb
        self.if_descr = []

    def _parse_options(self, opt_buf, checks):
        options = {}

        # If there is no option buffer (it is optional, after all), done.
        if not opt_buf:
            return options

        # Otherwise go through and get each option.
        found_end = False
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
                found_end = True
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
        if not found_end:
            raise PcapNGFileError("missing opt_endofopt option")

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
    def _parse_section_header_block(self, buf):
        # The byte order should have been checked in _read_block().

        # Verify our buffer is long enough.
        if len(buf) < 16:
            raise PcapNGFileError("section header block too short")

        # Check out version.
        ver_maj, ver_min = struct.unpack(self.byte_order+"HH", buf[4:8])
        if (ver_maj != 1) or (ver_min != 0):
            raise PcapNGFileError("Pcap NG format unsupported")

        # Grab our section length (-1 means "unspecified")
        section_len, = struct.unpack(self.byte_order+"q", buf[8:16])

        # Parse the options
        options = self._parse_options(buf[16:], OPTION_CHECKS_SHB)

        # Return what we found
        return SectionHeaderBlock(section_len=section_len, options=options)

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
        options = self._parse_options(buf[8:], OPTION_CHECKS_IF)
        return InterfaceDescriptionBlock(linktype=linktype,
                                         snaplen=snaplen,
                                         options=options)

    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #    +---------------------------------------------------------------+
    #  0 |                    Block Type = 0x00000006                    |
    #    +---------------------------------------------------------------+
    #  4 |                      Block Total Length                       |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  8 |                         Interface ID                          |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 12 |                        Timestamp (High)                       |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 16 |                        Timestamp (Low)                        |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 20 |                    Captured Packet Length                     |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 24 |                    Original Packet Length                     |
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # 28 /                                                               /
    #    /                          Packet Data                          /
    #    /              variable length, padded to 32 bits               /
    #    /                                                               /
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    /                                                               /
    #    /                      Options (variable)                       /
    #    /                                                               /
    #    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |                      Block Total Length                       |
    #    +---------------------------------------------------------------+
    def _parse_epb_block(self, buf):
        """
        Parse the Enhance Packet Block buffer without the block type
        and block total length values.
        """
        if len(buf) < 20:
            raise PcapNGFileError("enhanced packet block too short")
        (interface_id,
         timestamp_hi, timestamp_lo,
         capture_len, original_len) = struct.unpack(self.byte_order+"IIIII",
                                                    buf[:20])
        if interface_id > len(self.if_descr):
            raise PcapNGFileError("invalid interface identifier")
        if capture_len > original_len:
            raise PcapNGFileError("capture length too big")

        # figure out the time
        if_descr_opt = self.if_descr[interface_id].options
        if_ts_resol = if_descr_opt.get("if_tsresol", DEFAULT_TS_RESOL)
        timestamp = (timestamp_hi << 32) + timestamp_lo
        pkt_time = decimal.Decimal(timestamp) / decimal.Decimal(if_ts_resol)
        print(time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(pkt_time)) +
              str(pkt_time - math.floor(pkt_time))[1:])

        pkt_data = buf[20:20+capture_len]
        if len(pkt_data) != capture_len:
            raise PcapNGFileError("enhanced packet block missing packet data")

        padded_capture_len = capture_len + ((4 - (capture_len % 4)) % 4)
        options = self._parse_options(buf[20+padded_capture_len:],
                                      OPTION_CHECKS_EPB)
        return (options, interface_id, pkt_time,
                capture_len, original_len, pkt_data)

    def _read_block(self):
        """
        Read a block.
        """
        # Read the block type and block length.
        header_buf = self.file.read(8)

        # Handle EOF
        if len(header_buf) == 0:
            raise EOFError()

        if len(header_buf) != 8:
            raise PcapNGFileError("block missing header")

        # Handle the special case of section header block, which includes
        # the byte order magic.
        if header_buf[0:4] == bytes([0x0A, 0x0D, 0x0D, 0x0A]):
            byte_order_magic = self.file.read(4)
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
            buf = byte_order_magic
        else:
            buf = b''

        blk_type, blk_len = struct.unpack(self.byte_order+"II", header_buf)
        if (blk_len % 4) != 0:
            raise PcapNGFileError("block length not multiple of 4")

        # Read the rest of the block, based on block length.
        buf += self.file.read(blk_len - len(buf) - 8)
        if len(buf) != blk_len - 8:
            raise PcapNGFileError("block truncated")

        # Check the final block length value.
        blk_len_check, = struct.unpack(self.byte_order+"I", buf[-4:])
        if blk_len != blk_len_check:
            raise PcapNGFileError("block length not duplicated")

        # Return the block information
        return blk_type, buf[:-4]

    def read_pkt(self):
        while True:
            blk_type, buf = self._read_block()
            if blk_type == BLK_TYPE_SHB:
                self.shb = self._parse_section_header_block(buf)
                # reset the list of interfaces for each section
                self.if_descr = []
            elif blk_type == BLK_TYPE_IF:
                self.if_descr.append(self._parse_if_block(buf))
            elif blk_type == BLK_TYPE_EPB:
                (pkt_options,
                 pkt_interface_id,
                 pkt_timestamp,
                 pkt_capture_len,
                 pkt_original_len,
                 pkt_data) = self._parse_epb_block(buf)
                print(pkt_options)
                print(pkt_interface_id)
                print(pkt_timestamp)
                print(pkt_capture_len)
                print(pkt_original_len)
                return blk_type
            else:
                return blk_type, buf


if __name__ == '__main__':
    with open('delme.pcap', 'rb') as my_fp:
        pcapf = PcapNGFile(my_fp)
        print(pcapf.shb)
        pcapf.read_pkt()
        pcapf.read_pkt()
        pcapf.read_pkt()
        pcapf.read_pkt()
        pcapf.read_pkt()
