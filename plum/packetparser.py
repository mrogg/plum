"""Parse raw packets to get usable nested dicts.

Here is a little guide to what gets populated where by the
packet parser and what types of values you will see.

[PacketParser.__call__] (added to root dict)

ts: time stamp (int)
rp: raw packet (str)
dev: device (str)
pos: position (int)
layer2: enum(ethernet,)
layer3: enum(ip,)
layer4: enum(tcp,)
ip: ip header info (dict)
tcp: tcp header info (dict)
data: tcp payload (str)

[PacketParser.parse_ethernet] (added to root dict)

dst_mac: destination MAC (colon separated hex)
src_mac: source MAC (colon separated hex
type: ethertype (hex)

[PacketParser.parse_ip] (added to ip info)

ver: version (int)
hdr_len: number of 32 bit words (int)
tos: not implemented
len: total length of ip packet in bytes (int)
id: for fragments and worse (int)
flags: dict of what flags bits indicate
frag_offset: number of 8 byte blocks (int)
ttl: time to live in seconds (int)
proto: indicates carried protocol (int, 6 for TCP)
hdr_checksum: not implemented
src_addr: in dot notation (str)
dst_addr: in dot notation (str)
opts: not implemented

[PacketParser.parse_tcp] (added to tcp info)

src_port: (int)
dst_port: (int)
seq_num: (int)
ack_num: (int)
hdr_len: number of 32 bit words (int)
reserved: not implemented
flags: dict of flag bits options 
window: number of bytes (int)
checksum: not implemented
urgency: not implemented
options: not implemented

"""

import struct


class PacketParser(object):
    """Extract header info and data from a packet as a string of bytes.

    Parses ethernet, ip, and tcp
    These preped, nested packet dicts can then be post-processed to
    assemble tcp conversations and higher layer exchanges.
    (See plum.tcpcollector.TCPCollector.)
    """
    # TODO: What are the right words for the above docstring?

    def __init__(self, cfg, log):
        """Init with config (ConfigParser instance)."""
        self.cfg = cfg
        self.log = log

    def parse_ethernet(self, raw_packet):
        """Return info about raw ethernet packet as dict."""
        header_parts = struct.unpack('!6c6cH', raw_packet[:14])
        dst_mac = ':'.join(['%.2x' % ord(c) for c in header_parts[:6]])
        src_mac = ':'.join(['%.2x' % ord(c) for c in header_parts[6:12]])
        ether_type = hex(header_parts[12])
        info = {'dst_mac': dst_mac,
                'src_mac': src_mac,
                'type': ether_type}
        return info, raw_packet[14:]

    def parse_ip(self, raw_packet):
        """Parse raw packet and return IP info dict."""
        ver = ord(struct.unpack('!c', raw_packet[0])[0]) >> 4
        hdr_len = ord(struct.unpack('!c', raw_packet[0])[0]) & 15
        # tos - 1 - maybe TODO
        #tos = {'precedence': 0}
        len = struct.unpack('!H', raw_packet[2:4])[0]
        id = struct.unpack('!H', raw_packet[4:6])[0]
        flags_byte = ord(struct.unpack('!c', raw_packet[6])[0])
        flags = {'R': flags_byte >> 7 & 1,
                 'DF': flags_byte >> 6 & 1,
                 'MF': flags_byte >> 5 & 1}
        frag_offset = struct.unpack('!H', raw_packet[6:8])[0] & 8191
        ttl = ord(struct.unpack('!c', raw_packet[8])[0])
        proto = ord(struct.unpack('!c', raw_packet[9])[0])
        #hdr_checksum - 10-11  - maybe TODO
        src_addr = '.'.join([str(ord(c)) for c 
                             in struct.unpack('!cccc', raw_packet[12:16])])
        dst_addr = '.'.join([str(ord(c)) for c 
                             in struct.unpack('!cccc', raw_packet[16:20])])
        #opts - may or may not be here - TODO

        info = {'ver': ver,
                'hdr_len': hdr_len,
                'tos': 'Not Implemented',
                'len': len,
                'id': id,
                'flags': flags,
                'frag_offset': frag_offset,
                'ttl': ttl,
                'proto': proto,
                'hdr_checksum': 'Not Implemented',
                'src_addr': src_addr,
                'dst_addr': dst_addr,
                'opts': 'Not Implemented'}
        # Internet Header Length, IHL, is number of 32 bit words.
        header_byte_len = hdr_len * 4
        # Need to specify end of data because there may be some 
        # Ethernet padding at the end (to make it 60 bytes).
        return info, raw_packet[header_byte_len:len]

    def parse_tcp(self, raw_packet):
        """Return TCP info about raw packet as dict."""
        # TODO: Full header coverage? Config driven?
        src_port = struct.unpack('!H', raw_packet[0:2])[0]
        dst_port = struct.unpack('!H', raw_packet[2:4])[0]
        seq_num = struct.unpack('!I', raw_packet[4:8])[0]
        ack_num = struct.unpack('!I', raw_packet[8:12])[0]
        hdr_len = ord(struct.unpack('!c', raw_packet[12])[0]) >> 4
        # tcp_reserved: 12, last 4 bits
        flags_byte = ord(struct.unpack('!c', raw_packet[13])[0])
        flags = {'CWR': flags_byte >> 7 & 1,
                 'ECE': flags_byte >> 6 & 1,
                 'URG': flags_byte >> 5 & 1,
                 'ACK': flags_byte >> 4 & 1,
                 'PSH': flags_byte >> 3 & 1,
                 'RST': flags_byte >> 2 & 1,
                 'SYN': flags_byte >> 1 & 1,
                 'FIN': flags_byte & 1,}
        window = struct.unpack('!H', raw_packet[14:16])[0]
        #checksum - 16:18
        #urg - 18:20
        #options - may be set
        info = {'src_port': src_port,
                'dst_port': dst_port,
                'seq_num': seq_num,
                'ack_num': ack_num,
                'hdr_len': hdr_len,
                'reserved': 'Not Implemented',
                'flags': flags,
                'window': window,
                'checksum': 'Not Implemented',
                'urgency': 'Not Implemented',
                'options': 'Not Implemented'}

        # Data offset, is number of 32 bit words.
        header_byte_len = hdr_len * 4
        return info, raw_packet[header_byte_len:]

    def __call__(self, time_stamp, raw_packet, dev, pos):
        """Turn a raw packet into a usable dict. 

        Assumes Ethernet/IP/TCP[/SSL]/HTTP) but you can still get stats up
        to the layer of the lowest unsupported protocol.
        (As of 01/07/2008, that just means TCP and HTTP stats, of course.)
        """
        packet, rest = self.parse_ethernet(raw_packet)
        packet['ts'] = time_stamp
        packet['rp'] = raw_packet[:] # Why copy?
        packet['dev'] = dev
        packet['pos'] = pos
        packet['layer2'] = 'ethernet'
        # Only parse if payload is IP, # TODO: else log?
        if packet['type'] == '0x800':
            packet['layer3'] = 'ip'
            ip_info, rest = self.parse_ip(rest)
            packet['ip'] = ip_info
            # Only parse if payload is TCP. # TODO: else log?
            if ip_info['proto'] == 6:
                packet['layer4'] = 'tcp'
                packet['tcp'], packet['data'] = self.parse_tcp(rest)
        return packet
