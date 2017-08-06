import sys

# Normally you can just use "import pycaponic", but if we cannot
# import it, try again adding the parent directory. This lets us run
# from the source tree.
try:
    import pycaponic
except ImportError:
    sys.path.append("..")
    import pycaponic

def process(handle):
    for packet in pycaponic.packets(handle):
        broadcast = False
        if packet.epb_flags is not None:
            if packet.epb_flags.reception == "broadcast":
                broadcast = True
        if packet.mac_dst in ("FF-FF-FF-FF-FF-FF", "FF-FF-FF-FF-FF-FF-FF-FF"):
            broadcast = True
        if broadcast:
            print("%s -> BROADCAST" % packet.timestamp)
        else:
            print("%s -> not broadcast" % packet.timestamp)

def main():
    # get the list of files
    files = sys.argv[1:]
    # if not files were specified, read from stdin
    if not files:
        files = "-"
    # process each file separately
    for fname in files:
        if fname == "-":
            process(sys.stdin.buffer)
        else:
            with open(fname, "rb") as handle:
                process(handle)

if __name__ == '__main__':
    main()
