import sys
import time

from pycaponic.linklayer import Decoder, LINKTYPES, LINK_DECODERS
from pycaponic.PcapFile import PcapFile
from pycaponic.PcapNGFile import PcapNGFile


class EncapsulatedPacketException(Exception):
    pass


def _hexdump(data, out):
    ofs = 0
    while data:
        blk = data[:16]
        data = data[16:]

        hexval0 = [("%02x" % b) for b in blk[:8]]
        hexval1 = [("%02x" % b) for b in blk[8:]]
        hexstr = " ".join(hexval0) + "  " + " ".join(hexval1)

        cleanval = [chr(b) if (32 <= b < 127) else '.' for b in blk]
        cleanstr = ''.join(cleanval)

        out.write("%08x  %-49s  |%-16s|\n" % (ofs, hexstr, cleanstr))

        ofs += 16


class EncapsulatedPacket:
    def dump(self, out=sys.stdout, dump_contents=False):
        out.write("cap_type = %s\n" % self.cap_type)
        out.write("version = %s\n" % self.version)
        out.write("snaplen = %d\n" % self.snaplen)
        out.write("linktype = %s\n" % LINKTYPES[self.linktype])
        sec = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.timestamp))
        sec_fract = ("%f" % (self.timestamp % 1))[1:]
        out.write("timestamp = %s%s\n" % (sec, sec_fract))
        out.write("origlen = %d\n" % self.origlen)
        out.write("caplen = %d\n" % self.caplen)
        out.write("pkttype = %s\n" % self.pkttype)
        mac_src = getattr(self, "mac_src")
        if mac_src:
            out.write("mac_src = %s\n" % mac_src)
        mac_dst = getattr(self, "mac_dst")
        if mac_dst:
            out.write("mac_dst = %s\n" % mac_dst)
        for attr in sorted(dir(self)):
            if (attr.startswith("shb_") or attr.startswith("if_") or
               attr.startswith("epb_")):
                out.write(attr + " = " + getattr(self, attr) + "\n")
        if dump_contents:
            _hexdump(self.data, out)


def _read_pcapfile(fp, header_buf):
    pcapfp = PcapFile(fp, header_buf)
    decoder = Decoder(pcapfp.network, pcapfp.byte_order)
    try:
        while True:
            pkt_hdr, buf = pcapfp.read_pkt()

            pkt = EncapsulatedPacket()
            pkt.cap_type = 'pcap'
            pkt.version = '2.4'
            pkt.snaplen = pcapfp.snaplen
            pkt.linktype = pcapfp.network
            pkt.timestamp = pkt_hdr.timestamp
            pkt.origlen = pkt_hdr.orig_len
            pkt.caplen = len(buf)
            pkt.data, pkt.pkttype, link_metadata = decoder.decode(buf)
            if "mac_src" in link_metadata:
                pkt.mac_src = link_metadata["mac_src"]
            if "mac_dst" in link_metadata:
                pkt.mac_dst = link_metadata["mac_dst"]
            yield pkt
    except EOFError:
        pass


def _read_pcapngfile(fp, header_buf):
    pcapngfp = PcapNGFile(fp, header_buf)
    try:
        while True:
            epb, ifb, shb = pcapngfp.read_pkt()

            pkt = EncapsulatedPacket()
            pkt.cap_type = 'pcapng'
            pkt.version = '1.0'
            pkt.snaplen = ifb.snaplen
            pkt.linktype = ifb.linktype
            pkt.timestamp = epb.timestamp
            pkt.origlen = epb.original_len
            pkt.caplen = epb.capture_len
            decoder = LINK_DECODERS.get(ifb.linktype)
            if not decoder:
                msg = "unknown link type 0x04X on interface" % ifb.linktype
                raise EncapsulatedPacketException(msg)
            pkt.data, pkt.pkttype, link_metadata = decoder(pcapngfp.byte_order,
                                                           epb.pkt_data)
            if "mac_src" in link_metadata:
                pkt.mac_src = link_metadata["mac_src"]
            if "mac_dst" in link_metadata:
                pkt.mac_dst = link_metadata["mac_dst"]

            # since "opt_comment" can appear in every block, we
            # rename it based on which block it appears in
            if "opt_comment" in shb.options:
                pkt.shb_comment = shb.options["opt_comment"]
            if "opt_comment" in ifb.options:
                pkt.if_comment = ifb.options["opt_comment"]
            if "opt_comment" in epb.options:
                pkt.epb_comment = epb.options["opt_comment"]

            # other options get added
            for opt_name, opt_val in shb.options.items():
                if opt_name != "opt_comment":
                    setattr(pkt, opt_name, opt_val)
            yield pkt
    except EOFError:
        pass


def packets(fp):
    file_type = fp.read(4)
    if len(file_type) < 4:
        raise EncapsulatedPacketException("pcap/PcapNG header too small")
    if file_type in (bytes([0xa1, 0xb2, 0xc3, 0xd4]),
                     bytes([0xd4, 0xc3, 0xb2, 0xa1])):
        for pkt in _read_pcapfile(fp, file_type):
            yield pkt
    elif file_type == bytes([0x0a, 0x0d, 0x0d, 0x0a]):
        for pkt in _read_pcapngfile(fp, file_type):
            yield pkt
    else:
        file_type_hex = "0x" + "".join("%02X" % c for c in list(file_type))
        msg = "unrecognized header " + file_type_hex
        raise EncapsulatedPacketException(msg)
