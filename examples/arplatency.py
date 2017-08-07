"""
In this example, we look for latency induced by the ARP protocol.

ARP is the way that a host tries to figure out which MAC address is
using an IP address on a LAN. It does this by sending a broadcast
packet asking "who has this IP address" and listening for where the
response comes from. This is documented in RFC 826:

https://tools.ietf.org/html/rfc826

We can look at the time between the ARP request and the ARP response
and figure out the extra latency added by this.
"""

import socket
import struct
import sys

# Normally you can just use "import pycaponic", but if we cannot
# import it, try again adding the parent directory. This lets us run
# from the source tree.
try:
    import pycaponic
    import pycaponic.linklayer
except ImportError:
    try:
        sys.path.append(".")
        import pycaponic
        import pycaponic.linklayer
    except ImportError:
        sys.path.append("..")
        import pycaponic
        import pycaponic.linklayer


class ARPError(Exception):
    """Exception raised when we have problems parsing an ARP packet"""
    pass


# ARP operations
ARES_OP_REQUEST = 1
ARES_OP_REPLY = 2


def get_arp_info(pkt):
    """
    Break the ARP packet into its components.
    """
    if len(pkt) < 8:
        raise ARPError("ARP header too short")
    ar_hrd, ar_pro, ar_hln, ar_pln, ar_op = struct.unpack("!HHBBH", pkt[0:8])
    pkt_len = 8+(2*ar_hln)+(2*ar_pln)
    if len(pkt) < pkt_len:
        raise ARPError("ARP packet too short")
    ofs = 8
    ar_sha = pkt[ofs:ofs+ar_hln]
    ofs += ar_hln
    ar_spa = pkt[ofs:ofs+ar_pln]
    ofs += ar_pln
    ar_tha = pkt[ofs:ofs+ar_hln]
    ofs += ar_hln
    ar_tpa = pkt[ofs:ofs+ar_pln]
    ofs += ar_pln
    return (ar_hrd, ar_pro, ar_hln, ar_pln,
            ar_op, ar_sha, ar_spa, ar_tha, ar_tpa)


def measure_arp_latency(handle):
    """
    Look for ARP requests followed by an ARP response, and calculate
    the latency of the response.

    Note that ARP requests asking for the machine that is capturing
    packets will always have low latency from this measurement,
    because the capture doesn't see any network latency.
    """

    # Keep every request seen in a dictionary. In a "real" program
    # similar to this you would probably want to periodically delete
    # unanswered ARP requests.
    arp_requests = {}

    for packet in pycaponic.packets(handle):
        # Only bother with ARP packets.
        if packet.pkttype != 'ARP':
            continue

        try:
            (_, ar_pro, _, _,
             ar_op, _, ar_spa, _, ar_tpa) = get_arp_info(packet.data)
            # Only handle IPv4 ARP packets. (I'm not even sure any other
            # protocol actually uses ARP...)
            if ar_pro == pycaponic.linklayer.ETHERTYPE_IPv4:
                # For requests, just save the request.
                if ar_op == ARES_OP_REQUEST:
                    key = (ar_spa, ar_tpa)
                    arp_requests[key] = packet
                # For replies, see if we have a request and calculate the
                # latency if so.
                elif ar_op == ARES_OP_REPLY:
                    key = (ar_tpa, ar_spa)
                    if key in arp_requests:
                        request_packet = arp_requests[key]
                        del arp_requests[key]
                        latency = packet.timestamp - request_packet.timestamp
                        ip_requestor = socket.inet_ntop(socket.AF_INET, ar_tpa)
                        ip_responder = socket.inet_ntop(socket.AF_INET, ar_spa)
                        print("%s %-15s %-15s" % (latency,
                                                  ip_requestor, ip_responder))
        except ARPError:
            # ignore broken packets
            pass


def main():
    """Program entry point"""
    measure_arp_latency(sys.stdin.buffer)


if __name__ == '__main__':
    main()
