"""
Open and read pcap files.

https://wiki.wireshark.org/Development/LibpcapFileFormat
"""
import collections
import decimal
import struct


class PcapFileError(Exception):
    pass


# time resolution
USEC = decimal.Decimal('0.000001')


PacketHeader = collections.namedtuple('PacketHeader', ['timestamp',
                                                       'incl_len', 'orig_len'])


class PcapFile:
    def __init__(self, fp, header_buf=b''):
        self.file = fp

        buf = header_buf + self.file.read(24-len(header_buf))
        if len(buf) < 24:
            raise PcapFileError("global header too small")

        magic_number, = struct.unpack("<I", buf[0:4])
        if magic_number == 0xa1b2c3d4:
            self.byte_order = "<"
        else:
            magic_number, = struct.unpack(">I", buf[0:4])
            if magic_number == 0xa1b2c3d4:
                self.byte_order = ">"
            else:
                raise PcapFileError("bad byte order magic")

        ver_maj, ver_min = struct.unpack(self.byte_order+"HH", buf[4:8])
        if (ver_maj != 2) or (ver_min != 4):
            raise PcapFileError("pcap version unsupported")

        (self.thiszone,
         self.sigfigs,
         self.snaplen,
         self.network) = struct.unpack(self.byte_order+"iIII", buf[8:24])

        # TODO: we might want to warn on non-zero sigflags

    def read_pkt(self):
        header = self.file.read(16)
        if header == b'':
            raise EOFError()
        if len(header) < 16:
            raise PcapFileError("packet header too small")

        (ts_sec, ts_usec,
         incl_len, orig_len) = struct.unpack(self.byte_order+"IIII", header)

        # calculate the time
        ts_sec += self.thiszone
        pkt_time = ts_sec + (ts_usec * USEC)

        # read the actual packet data
        buf = self.file.read(incl_len)
        if len(buf) < incl_len:
            raise PcapFileError("packet truncated")

        pkt_hdr = PacketHeader(timestamp=pkt_time,
                               incl_len=incl_len, orig_len=orig_len)

        return pkt_hdr, buf
