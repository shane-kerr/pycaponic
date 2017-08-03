import sys
import time

from yapcap.linklayer import Decoder, LINKTYPES
from yapcap.PcapFile import PcapFile

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
        if dump_contents:
            _hexdump(self.data, out)

def _read_pcapfile(fp, header_buf):
    pcap_type = 'pcap'
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

def packets(fp):
    file_type = fp.read(4)
    if len(file_type) < 4:
        raise EncapsulatedPacketException("pcap/PcapNG header too small")
    if file_type in (bytes([0xa1, 0xb2, 0xc3, 0xd4]), 
                     bytes([0xd4, 0xc3, 0xb2, 0xa1])):
        for pkt in _read_pcapfile(fp, file_type):
            yield pkt
    elif file_type == b'':
        pass
