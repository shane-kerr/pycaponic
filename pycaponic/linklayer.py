"""
Parse link-layer headers used by pcap and pcap-ng capture files:

http://www.tcpdump.org/linktypes.html
"""
import struct
from pycaponic.pycaponicError import pycaponicError

# TODO: handle unknown EtherType values

# https://en.wikipedia.org/wiki/EtherType
ETHERTYPE_IPv4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPv6 = 0x86DD

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

LINKTYPES = {
    LINKTYPE_NULL: "BSD loopback encapsulation",
    LINKTYPE_ETHERNET: "Ethernet",
    LINKTYPE_RAW: "raw IP",
    LINKTYPE_LOOP: "OpenBSD loopback encapsulation",
    LINKTYPE_IPV4: "IPv4",
    LINKTYPE_IPV6: "IPv6",
    LINKTYPE_LINUX_SLL: "Linux cooked-mode capture (SLL)",
}


class LinkLayerError(pycaponicError):
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
    elif ethertype == ETHERTYPE_ARP:
        pkt_type = "ARP"
    else:
        pkt_type = "EtherType 0x%04X" % ethertype
    info = {"mac_dst": mac_dst, "mac_src": mac_src, }
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
    return link_pkt, pkt_type, {}


def decode_loop(_, link_pkt):
    return decode_null("!", link_pkt)


def decode_ipv4(_, link_pkt):
    return link_pkt, "IPv4", {}


def decode_ipv6(_, link_pkt):
    return link_pkt, "IPv6", {}


# Values documented in the packet(7) man page, pulled from the
# linux/if_packet.h header.
SLL_PKT_TYPES = {
    0: 'PACKET_HOST',
    1: 'PACKET_BROADCAST',
    2: 'PACKET_MULTICAST',
    3: 'PACKET_OTHERHOST',
    4: 'PACKET_OUTGOING',
}


# Select values pulled from the if_arp.h header.
LINUX_ARPHDR_TYPES = {
    1: "ARPHDR_ETHER",
    768: "ARPHDR_TUNNEL",
    769: "ARPHDR_TUNNEL6",
    772: "ARPHDR_LOOPBACK",
    776: "ARPHDR_SIT",
    823: "ARPHDR_IP6GRE",
    824: "ARPHDR_NETLINK",
    825: "ARPHDR_6LOWPAN",
}


def decode_linux_sll(_, link_pkt):
    (sll_pkttype_val,
     sll_hatype_val,
     sll_halen) = struct.unpack("!HHH", link_pkt[0:6])
    sll_addr = link_pkt[6:14]
    sll_addr = sll_addr[:sll_halen]
    sll_addr = '-'.join(["%02X" % octet for octet in sll_addr])
    sll_protocol, = struct.unpack("!H", link_pkt[14:16])
    try:
        sll_pkttype = SLL_PKT_TYPES[sll_pkttype_val]
    except KeyError:
        msg = "unknown type {} of Linux SLL packet".format(sll_pkttype)
        raise LinkLayerError(msg)
    try:
        sll_hatype = LINUX_ARPHDR_TYPES[sll_hatype_val]
    except KeyError:
        sll_hatype = "Unknown ARPHDR type " + str(sll_hatype_val)

    if sll_protocol == ETHERTYPE_IPv4:
        pkt_type = "IPv4"
        sll_protocol = 'ETHERTYPE_IPv4'
    elif sll_protocol == ETHERTYPE_IPv6:
        pkt_type = "IPv6"
        sll_protocol = 'ETHERTYPE_IPv6'
    elif sll_protocol == ETHERTYPE_ARP:
        pkt_type = "ARP"
        sll_protocol = 'ETHERTYPE_ARP'
    else:
        pkt_type = "EtherType 0x%04X" % sll_protocol
        sll_protocol = str(sll_protocol)

    info = {
        'sll_pkttype': sll_pkttype,
        'sll_hatype': sll_hatype,
        'sll_halen': sll_halen,
        'sll_addr': sll_addr,
        'sll_protocol': sll_protocol,
    }

    return link_pkt[16:], pkt_type, info


LINK_DECODERS = {
    LINKTYPE_NULL: decode_null,
    LINKTYPE_ETHERNET: decode_ethernet,
    LINKTYPE_RAW: decode_raw,
    LINKTYPE_LOOP: decode_loop,
    LINKTYPE_IPV4: decode_ipv4,
    LINKTYPE_IPV6: decode_ipv6,
    LINKTYPE_LINUX_SLL: decode_linux_sll,
}


class Decoder:
    def __init__(self, link_type, byte_order):
        decoder = LINK_DECODERS.get(link_type)
        if not decoder:
            raise LinkLayerError("unknown link type #" + str(link_type))
        self.decoder = decoder
        self.byte_order = byte_order

    def decode(self, pkt):
        return self.decoder(self.byte_order, pkt)
