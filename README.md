# pycaponic: a Pythonic pcap module

This module allows you to easily read pcap and PcapNG files in Python.

I was looking around for a pcap library to use to read at some DNS
captures, and struggled to find one that was well-maintained, supports
Python 3, supports both pcap and pcapng formats, and had an intuitive
API. Eventually I decided to roll my own.

## General Usage

Usage is something like this:

```python
with open('myfile.pcap', 'rb') as pcapfp:
    for packet in pycaponic.packets(pcapfp):
        # access metadata as packet.timestamp, packet.info.pkt_type, ...
        # access contents as packet.data
```

If you have compressed packet captures, you may want to do use
something like the `gzip` or `bz2` modules to read them:

```python
with gzip.open('myfile.pcap.gz') as pcapfp:
    for packet in pcaponic.packets(pcapfp):
        ...
```

You can find some examples in the `examples` directory.

## Exceptions

If an error is found in the input file, a pycaponicError will be raised.
pcap and PcapNG files have their own classes:

```
+-- pycaponicError
    |
    +-- PcapError
    |
    +---PcapNGError
```

Each exception raised includes an error message that only appears in a
single place in the code, in case you want to look at the code which
raised the error and try to figure out why you got it.

## Metadata

The following metadata is present for all packets:

| Name        | Description |
|-------------|-------------|
| `cap_type`  | Either 'pcap' or 'pcapng' |
| `version`   | Version of pcap ("2.4") or PcapNG ("1.0") |
| `snaplen`   | Maximum length of a captured packet |
| `linktype`  | The type of link-layer header metadata for the packet |
| `timestamp` | The epoch value where the packet arrived, as a `decimal.Decimal` value |
| `origlen`   | The original length of the packet |
| `caplen`    | The captured length of the packet |
| `pkttype`   | The type of the packet: IPv4, IPv6, ARP, OSI, IPX, or "EtherType 0xNNNN" |

We use a `decimal.Decimal` type for the timestamp because the
precision of the timestamps in the file may be too much to fit in a
`float` type or `datetime.datetime` object (both only support
microsecond accuracy).

Note that the packet returned in `pkt.data` has the encapsulation
information removed.

## Link-layer Header Metadata

Depending on the format used, there may be additional link-level
header information.

The pycaponic package currently supports:

* LINKTYPE_NULL
* LINKTYPE_ETHERNET
* LINKTYPE_RAW
* LINKTYPE_LOOP
* LINKTYPE_IPV4
* LINKTYPE_IPV6

If the `link_type` is `LINKTYPE_ETHERNET`, then the packet metadata
will also have the source and destination MAC address of the packet:

| Name        | Description |
|-------------|-------------|
| `mac_src`   | The source MAC address of the packet, as a string like `"70-85-C2-3B-E8-F0"` |
| `mac_dst`   | The destination MAC address of the packet, as a string like `"00-01-2E-78-08-B1"` |

The full list of link-layer header types can be found here:

http://www.tcpdump.org/linktypes.html

For PCAP files, the link-level header is the same for all packets in
the capture. For PcapNG, each packet may have different link-level
header types.

## pcap Files

pcap files can be read directly using the PcapFile class. You will
probably want to decode the captured data using the linklayer.Decoder
class. At end of file an `EOFError` exception is raised.

```python
with open('oldschool.pcap', 'rb') as fp:
    pcapfile = pycaponic.PcapFile(fp)
    decoder = pycaponic.linklayer.Decoder(pcapfile.network,
                                          pcapfile.byte_order)
    try:
        while True:
            pkt_hdr, cap_data = pcapfile.read_pkt()
            # should check for truncation first
            pkt_data, pkt_type, pkt_info = decoder.decode(cap_data)
            # do something with pkt_hdr or pkt_data
    except EOFError:
        pass
```

## PcapNG Files

The PcapNG format provides a lot of additional information beyond what
pcap does. It is structured in blocks, which may provide packet
information, or may provide other information such as starting a new
block, or defining interface characteristics.

The following additional information may be present for a packet in a
PcapNG file:

| Name        | Description |
|-------------|-------------|
| `shb_comment`    | Comment from the section header block |
| `shb_hardware`   | Hardware of the machine that wrote the capture |
| `shb_os`         | OS of the machine that wrote the capture, like `"Linux 4.11.0"` |
| `shb_userappl`   | Application that wrote the capture, like `"Dumpcap 1.12.1"` |
| `if_comment`     | Comment from the interface block |
| `if_name`        | Name of the interface, like `"eth0"` |
| `if_description` | Description of the interface, like `"WAN"` or `"VPN"` |
| `if_IPv4addr`    | List of IPv4 addresses, like `[ '192.0.2.1', '192.0.2.11', ...]` |
| `if_IPv6addr`    | List of IPv6 addresses, like `[ '::1', '2001:470:1::73', ...]` |
| `if_MACaddr`     | The MAC address of the interface, like `"70-85-C2-3B-E8-F0"` |
| `if_EUIaddr`     | The EUI address of the interface, like `"00-01-2E-78-08-B1-01-FC"` |
| `if_speed`       | Speed of the interface in bits per second |
| `if_tsresol`     | Resolution of timestamps (1000 means msec, 1000000 means usec, and so on) |
| `if_tzone`       | Time zone offset in seconds |
| `if_filter`      | Filter type and string, like `(0, "host 192.0.2.11 and port 53")`
| `if_os`          | OS of the machine that has the interface, like `"Windows 8"` |
| `if_fcslen`      | Length of Frame Check Sequence for this interface, in bits |
| `if_tsoffset`    | Timestamp offset in seconds |
| `epb_comment`    | Comment from the enhanced packet block |
| `epb_flags`      | Packet flags (see below for details) |
| `epb_hash`       | Hash type and value, like `("CRC32", b'\x80\x1f\xc8\x18')` |
| `epb_dropcount`  | Count of packets dropped since last packet captured |

`epb_flags` is a named tuple and contains the following members:

| Name          | Description |
|---------------|-------------|
| `in_out_pkt`  | Direction of the packet; "information not available", "inbound", or "outbound" |
| `reception`   | How packet was received; "not specified", "unicast", "multicast", "broadcast", or "promiscuous" |
| `fcs_len`     | The Frame Check Sequence for this packet (overrides `if_fcslen` if that exists), or `None` |
| `link_errors` | A set of errors on receiving this packet which may contain "symbol", "preamble", "start frame delimiter", "unaligned fram", "wrong inter-frame gap", "packet too short", and "CRC" |

Like pcap files, PcapNG files can be read directly, although using the
PcapNGFile class instead of the PcapFile. You will probably want to
decode the captured data, although this is slightly more complicated
than for pcap files since the interface used can be different for each
packet and may have a different link layer. At end of file an
`EOFError` exception is raised.

```python
with open('nextgen.pcap', 'rb') as fp:
    pcapngfile = pycaponic.PcapNGFile(fp)
    try:
        while True:
            pkt_block, if_block, sh_block = pcapngfile.read_pkt()
            # should verify we understand the linktype
            decode = linklayer[if_block.linktype]
            # should check for truncation first
            pkt_data, pkt_type, pkt_info = decode(pcapngfile.byte_order, 
                                                  pkt_block.pkt_data)
            # do something with pkt_hdr or pkt_data
    except EOFError:
        pass
```

## Performance Considerations

No attention has been given to performance, with the primary goal
being to build a robust, Pythonic module.

If things are running too slowly, you can use [PyPy](http://pypy.org/)
for your programs, which will probably result in much faster execution
times.
