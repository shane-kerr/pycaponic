"""
Parse link-layer headers used by pcap and pcap-ng capture files:

http://www.tcpdump.org/linktypes.html
"""
import struct

# https://en.wikipedia.org/wiki/EtherType
ETHERTYPE_IPv4 = 0x0800
ETHERTYPE_IPv6 = 0x86DD

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

class LinkLayerError(Exception):
    pass


def decode_null(byte_order, link_pkt):
    if len(link_pkt) < 4:
        raise LinkLayerError("BSD loopback packet too small")
    ethertype, = struct.unpack(byte_order+"I", link_pkt[0:4])
    if ethertype == 2:
        pkt_type = "IPv4"
    elif ethertype in (24, 28, 30):
        pkt_type = "IPv6"
    elif ethertype == 7:
        pkt_type = "OSI"
    elif ethertype == 23:
        pkt_type = "IPX"
    else:
        raise LinkLayerError("unknown type of BSD loopback packet")
    payload = link_pkt[4:]
    return payload, pkt_type, {}


def decode_ethernet(_, link_pkt):
    if len(link_pkt) < 14:
        raise LinkLayerError("Ethernet packet too small")
    mac_dst = "%02X-%02X-%02X-%02X-%02X-%02X" % tuple(link_pkt[0:6])
    mac_src = "%02X-%02X-%02X-%02X-%02X-%02X" % tuple(link_pkt[6:12])
    ethertype, = struct.unpack("!H", link_pkt[12:14])
    payload = link_pkt[14:]
    if ethertype == ETHERTYPE_IPv4:
        pkt_type = "IPv4"
    elif ethertype == ETHERTYPE_IPv6:
        pkt_type = "IPv6"
    else:
        raise LinkLayerError("unknown type of Ethernet packet")
    info = { "mac_dst": mac_dst, "mac_src": mac_src, }
    return payload, pkt_type, info

def decode_raw(_, link_pkt):
    if len(link_pkt) < 1:
        raise LinkLayerError("raw packet too small")
    ip_ver = (link_pkt[0] >> 4) & 0b1111
    if ip_ver == 6:
        pkt_type = "IPv6"
    elif ip_ver == 4:
        pkt_type = "IPv4"
    else:
        raise LinkLayerError("raw packet not IPv4 or IPv6")
    return payload, pkt_type, {}

def decode_loop(_, link_pkt):
    return decode_null("!", link_pkt)

def decode_ipv4(_, link_pkt):
    return payload, "IPv4", {}

def decode_ipv6(_, link_pkt):
    return payload, "IPv6", {}

LINK_DECODERS = {
    LINKTYPE_NULL: decode_null,
    LINKTYPE_ETHERNET: decode_ethernet,
    LINKTYPE_RAW: decode_raw,
    LINKTYPE_LOOP: decode_loop,
    LINKTYPE_IPV4: decode_ipv4,
    LINKTYPE_IPV6: decode_ipv6,
}


class Decoder:
    def __init__(self, link_type, byte_order):
        decoder = LINK_DECODERS.get(link_type)
        if not decoder:
            raise LinkLayerError("unknown link type")
        self.decoder = decoder
        self.byte_order = byte_order

    def decode(self, pkt):
        return self.decoder(self.byte_order, pkt)
