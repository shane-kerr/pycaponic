"""
This is a sample program which identifies the broadcast packets from
a pcap/PcapNG file.

If looking at a PcapNG, then the Enhanced Packet Block flags option is
checked (if it exists). If the packet reception is specified as
broadcast, then the packet is treated as broadcast.

If the source is pcap, or if no flags option is present, or if the
reception is not broadcast then the destination MAC address of the
packet is checked. If it is set to all-ones (FF-FF-FF-FF-FF-FF) then
the packet is treated as broadcast. (We also check for 64-bit all ones
MAC address, FF-FF-FF-FF-FF-FF-FF-FF, even though no link layer
encapsulation that we support actually reports 64-bit MAC addresses.)

For each packet, we print the time it arrive and whether it was a
broadcast packet or not. If it was broadcast, we also print the packet
type.
"""
import sys
import time

# Normally you can just use "import pycaponic", but if we cannot
# import it, try again adding the parent directory. This lets us run
# from the source tree.
try:
    import pycaponic
except ImportError:
    try:
        sys.path.append(".")
        import pycaponic
    except ImportError:
        sys.path.append("..")
        import pycaponic

def process(handle):
    """
    Process the packets from the file handle.
    """
    for packet in pycaponic.packets(handle):
        # packet.timestamp is the epoch time - the seconds since
        # 1970-01-01T00:00:00. It's a bit easier to read as an ISO
        # timestamp, and we also add the fractional seconds properly
        # with this utility function.
        when = pycaponic.epoch2iso8601(packet.timestamp)

        # Next try to figure out if this is a broadcast packet.
        broadcast = False
        # Check how it was received, if we know.
        if packet.epb_flags is not None:
            if packet.epb_flags.reception == "broadcast":
                broadcast = True
        # Otherwise see if the MAC address is all-ones.
        if packet.mac_dst in ("FF-FF-FF-FF-FF-FF", "FF-FF-FF-FF-FF-FF-FF-FF"):
            broadcast = True
        # Finally output whatever we discovered about each packet.
        if broadcast:
            print("%s -> BROADCAST (%s)" % (when, packet.pkttype))
        else:
            print("%s -> not broadcast" % when)

def main():
    # Get the list of files from the arguments.
    files = sys.argv[1:]
    # If no files were specified, read from stdin only.
    if not files:
        files = "-"
    # Process each file separately.
    for fname in files:
        if fname == "-":
            # We use "sys.stdin.buffer" for stdin because we need the
            # binary input stream. If performance is an issue then we
            # could assign a new, binary buffer to it.
            process(sys.stdin.buffer)
        else:
            with open(fname, "rb") as handle:
                process(handle)

if __name__ == '__main__':
    main()
