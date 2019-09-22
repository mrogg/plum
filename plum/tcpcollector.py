"""Collect TCP Packets and put back together the full conversation.

Uses pduassembler to reconstruct up-layer protocols, though it may 
use sslstriper to de-sslify it first. 
"""

import time


def compare_by_sequence(x, y):
    """Compare packets for sorting a list of them by TCP sequence number."""
    if x['tcp']['seq_num'] > y['tcp']['seq_num']:
        return 1
    else:
        return -1


class TCPCollector(object):
    """Keep state of given tcp packets and expire them as appropriate.

    Pass conversation to callback function when conversation is over 
    ended by both sides or reset by one.
    """

    def __init__(self, callback, cfg, log):
        """Init with storage callback."""
        self.store = callback
        self.cfg = cfg
        self.log = log
        self.conv = {}

        self.fin_wait_timeout = cfg.getint('housekeeping', 'fin_wait_timeout')
        # Set the next time that the fin cleanser should run
        self.next_fin_cleanse = time.time() + self.fin_wait_timeout

    def begin_convo(self, source_key, packet):
        """Start a new conversation for given source_key and packet."""
        if self.conv.get(source_key) is None:
            convo = {
                'in_pkts': [packet],
                'out_pkts': [],
                'start_ts': packet['ts'],
                'bytes': packet['ip']['len'] + 14,
                'in_bytes': packet['ip']['len'] + 14,
                'out_bytes': 0,
                'src_ip': packet['ip']['src_addr'],
                'src_port': packet['tcp']['src_port'],
                'dst_ip': packet['ip']['dst_addr'],
                'dst_port': packet['tcp']['dst_port'],
                'pkt_cnt': 1,
                'dev': packet['dev'],
                'start_pos': packet['pos'],
                'source_key': source_key,
            }
            self.conv[source_key] = convo
            return convo
        else:
            # TODO: Do something better here. 
            self.log.warn('Conversation Overwrite!')

    def update_conversation(self, convo, packet):
        """Update conversation stats and add the packet to the list."""
        convo['end_ts'] = packet['ts']
        convo['bytes'] += int(packet['ip']['len']) + 14
        convo['out_bytes'] += int(packet['ip']['len']) + 14
        convo['pkt_cnt'] += 1

    def handle_in_bound(self, convo, packet):
        """Add a client -> server packet to the appropriate conversation."""

        convo['in_pkts'].append(packet)

        # Latency between tap and client
        if packet['tcp']['flags']['ACK']: 
            if convo['syn_ack_num'] == (packet['tcp']['ack_num'] - 1):
                convo['latency'] = packet['ts'] - convo['syn_ack_ts']

        # Check if FIN by client
        if packet['tcp']['flags']['FIN']:
            convo['client_fin'] = packet['ts']

            if convo.get('server_fin') is not None:
                # Expire conversation
                convo['end_pos'] = packet['pos']
                try:
                    self.reconstruct(convo)
                    self.store(convo)
                finally:
                    # Make sure stuff gets deleted no matter what
                    del self.conv[convo['source_key']]
                    del convo

        # Check for RST by client
        if packet['tcp']['flags']['RST']:
            convo['client_rst'] = True
            convo['end_pos'] = packet['pos']
            try:
                self.reconstruct(convo)
                self.store(convo)
            finally:
                # Make sure stuff gets deleted no matter what
                del self.conv[convo['source_key']]
                del convo

    def handle_out_bound(self, convo, packet):
        """Add a server -> client packet to the appropriate conversation."""
        
        convo['out_pkts'].append(packet)
        
        # Latency between tap and Server
        if packet['tcp']['flags']['SYN'] and packet['tcp']['flags']['ACK']:
            convo['syn_ack_ts'] = packet['ts']
            # Server stack pktponse time
            convo['syn_ack_diff'] = packet['ts'] - convo['start_ts']
            convo['syn_ack_num'] = packet['tcp']['seq_num']

        # Check if FIN by server 
        if packet['tcp']['flags']['FIN']:
            convo['server_fin'] = packet['ts']

            if convo.get('client_fin') is not None:
                # Expire conversation
                convo['end_pos'] = packet['pos']
                try: 
                    self.reconstruct(convo)
                    self.store(convo)
                finally:
                    # Make sure stuff gets deleted no matter what
                    del self.conv[convo['source_key']]
                    del convo

        # Check for RST by server
        if packet['tcp']['flags']['RST']:
            convo['serv_rst'] = True
            convo['end_pos'] = packet['pos']
            try:
                self.reconstruct(convo)
                self.store(convo)
            finally:
                # Make sure stuff gets deleted no matter what
                del self.conv[convo['source_key']]
                del convo

    def fin_cleanse(self, current_ts):
        """Clean up conversations sitting in the fin-wait states"""

        if current_ts > self.next_fin_cleanse:
            old_time =  current_ts - self.fin_wait_timeout
            for conv_id in self.conv.keys():
                if (self.conv[conv_id].get('client_fin') 
                    and self.conv[conv_id]['client_fin'] < old_time):
                    self.log.error('Clt Fin wait timeout: %s' % conv_id)
                    try:
                        self.reconstruct(self.conv[conv_id])
                        self.store(self.conv[conv_id])
                    finally:
                        del self.conv[conv_id]
                if self.conv[conv_id].get('server_fin') and \
                    self.conv[conv_id]['server_fin'] < old_time:
                        self.log.error('Srv Fin wait timeout: %s' % conv_id)
                        try:
                            self.reconstruct(self.conv[conv_id])
                            self.store(self.conv[conv_id])
                        finally:
                            del self.conv[conv_id]

        self.next_fin_cleanse = current_ts + self.fin_wait_timeout

    def add(self, packet):
        """Add packet to internal self.conv state table. 

        If packet indicates self.conversation expiry, remove from
        internal state and pass to callback.
        """
        self.fin_cleanse(packet['ts'])

        source_key = '%s-%s' % (packet['ip']['src_addr'], 
                                packet['tcp']['src_port'])
        # If start of handshake create new conversation
        if packet['tcp']['flags']['SYN'] and not packet['tcp']['flags']['ACK']:
            convo = self.begin_convo(source_key, packet)
        # If not, then this should be part of an existing conversation
        else:
            destination_key = '%s-%s' % (packet['ip']['dst_addr'],
                                         packet['tcp']['dst_port']) 
            # Try to find an appropriate conversation and packet handler

            if source_key in self.conv: # Client -> Server
                convo = self.conv[source_key]
                handler = self.handle_in_bound
            elif destination_key in self.conv: # Server -> Client
                convo = self.conv[destination_key]
                handler = self.handle_out_bound
            else:
                # Ignore this packet because I don't know
                # of any such conversation. TODO something?
                return
            # deal with the packet.
            self.update_conversation(convo, packet)
            handler(convo, packet)

    @staticmethod
    def cleanse(packets):
        """Reorder packets and remove duplicates as appropriate"""
        pkts = []
        retran = False
        lost = False
        for pkt in packets:
            if len(pkt['data']) > 0:
                # If first packet just add and move on
                if len(pkts) == 0:
                    pkts.append(pkt)
                    next_seq = pkt['tcp']['seq_num'] + len(pkt['data'])
                # If next seq num is = to this one add this pkt
                elif pkt['tcp']['seq_num'] == next_seq:
                    pkts.append(pkt)
                    next_seq = pkt['tcp']['seq_num'] + len(pkt['data'])
                # If next seq num is > than this one there is a  
                # Retransmission
                elif pkt['tcp']['seq_num'] < next_seq:
                    retran = True
                elif pkt['tcp']['seq_num'] > next_seq:
                    lost = True
                else:
                    pass

        return pkts, retran, lost

    @staticmethod
    def reconstruct(convo):
        """Reconstruct the input and output tcp streams."""
        in_stream = []
        in_timeline = {}
        in_borders = []
        in_position = 0
        out_stream = []
        out_timeline = {}
        out_borders = []
        out_position = 0

        # Sort packets by sequence number and then timestamp
        convo['in_pkts'].sort(key=lambda i: (i['tcp']['seq_num'], i['ts']))
        convo['out_pkts'].sort(key=lambda i: (i['tcp']['seq_num'], i['ts']))

        # Get new list of data packets with any duplicate bytes removed
        in_pkts, in_retran, in_lost = TCPCollector.cleanse(convo['in_pkts'])
        out_pkts, out_retran, out_lost = TCPCollector.cleanse(convo['out_pkts'])

        #all_pkts = in_pkts + out_pkts
        #self.log.raw_packets(all_pkts)

        # Go through packets and rebuild tcp in/out stream 
        for pkt in in_pkts:
            in_stream.append(pkt['data'])
            in_timeline[in_position] = pkt['ts']
            in_borders.append(in_position)
            in_position += len(pkt['data']) 

        for pkt in out_pkts:
            out_stream.append(pkt['data'])
            out_timeline[out_position] = pkt['ts']
            out_borders.append(out_position)
            out_position += len(pkt['data']) 
                    
        convo['in_stream'] = "".join(in_stream)
        convo['in_timeline'] = in_timeline
        convo['in_borders'] = in_borders
        convo['in_retran'] = in_retran
        convo['in_lost'] = in_lost
        convo['out_stream'] = "".join(out_stream)
        convo['out_timeline'] = out_timeline
        convo['out_borders'] = out_borders
        convo['out_retran'] = out_retran
        convo['out_lost'] = out_lost
        return convo

