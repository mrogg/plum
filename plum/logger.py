"""Do logging for plum.

"""

import struct
import logging, logging.handlers


class Logger(object):

    def __init__(self, cfg):
        """."""
        self.cfg = cfg
        settings = dict(cfg.items('logging', raw=True))
        dump_file = settings['dump_file']
        self.dump_file = self._pcap_file(dump_file)

        #basicConfig(**cfg.logging)
        logger = logging.getLogger(settings['logger_id'])
        log_level = getattr(logging, settings['level'])
        logger.setLevel(log_level)
        formatter = logging.Formatter(settings['format'])
        rotateHandler = logging.handlers.RotatingFileHandler(
            settings['filename'],
            settings['filemode'],
            int(settings['maxsize']),
            int(settings['maxbackups'])
        )
        rotateHandler.setFormatter(formatter)
        logger.addHandler(rotateHandler)
        self.logger = logger

    def _pcap_file(self, path):
        """Return a handle to a file witha a pcap header at the top."""
        dump_file = file(path, 'w')
        pcap_header = struct.pack(
            'IHHIIII', 
            0xa1b2c3d4,
            2,
            4,
            0,
            0,
            65535,
            1,
        )
        dump_file.write(pcap_header)
        return dump_file

    def _write_packet(self, packet):
        """Dump a raw packet to the configured dump_file."""
        timestamp = packet['ts']
        raw_packet = packet['rp']
        packet_header = struct.pack(
            'IIII',
            int(timestamp),
            int((float(timestamp) - int(timestamp)) * 1000000),
            len(raw_packet),
            len(raw_packet),
        )

        self.dump_file.write(packet_header)
        self.dump_file.write(str(raw_packet))

    def negative_response_time(self, in_time, out_time, convo):
        self.error("""
            Bad Response Time. 
            Src Port: %s 
            Src IP: %s 
            Dst IP: %s
            # Pkts: %s
            in_time: %s
            out_time: %s
            clt rst: %s
            srv rst: %s
            clt fin: %s
            srv fin: %s
            in pdus: %s
            out pdus: %s
            """ % (
                convo['src_port'],
                convo['src_ip'],
                convo['dst_ip'],
                len(convo['in_pkts']) + len(convo['out_pkts']),
                in_time,
                out_time,
                convo.get('client_rst'),
                convo.get('server_rst'),
                convo.get('client_fin'),
                convo.get('server_fin'),
                len(convo['in_pdus']),
                len(convo['out_pdus']),
            )
        )
        self.raw_packets(convo['in_pkts'] + convo['out_pkts'])
        raise Exception, 'Bad Rsp Time'

    def raw_packets(self, packets):
        """Log a list of raw packets to the raw packet log"""
        packets.sort(key=lambda i: (i['ts']))
        for packet in packets:
            self._write_packet(packet) 
        self.dump_file.flush()

    def packet_summary(self, packet):
        """Log packet summary in DEBUG mode."""
        http = packet['data']
        summary = "\n\t%s:%s : %s:%s %s %s %s %s" % (
            packet['ip']['src_addr'],
            packet['tcp']['src_port'],
            packet['ip']['dst_addr'],
            packet['tcp']['dst_port'],
            packet['tcp']['seq_num'],
            packet['tcp']['ack_num'],
            len(http),
            packet['ts'],
        )
        summary += "\n\t%s" % packet['tcp']['flags']
        if http[:4] in ['GET ','POST ','HTTP']:
            summary += "\n\t\t %s" % repr(http)
        self.logger.debug(summary)

    def missing_packets(self, convo):
        """Log missing packets when parsing TCP conversations in DEBUG mode."""
        self.logger.debug(
            "Missing pkts in convo: %s\n\t%s, %s\n\t%s\n\t%s\n"
            % (convo['id'], 
               convo['src_port'], 
               convo['dst_port'],
               len(convo['in_pdus']),
               len(convo['out_pdus'])))

    def log_convo_description(self, convo):
        """Log a description of key properties of this conversation."""

    def weird_http(self, *args):
        """Log exception case when parsing out PDUs, in DEBUG mode."""
        # TODO: Improve this.
        self.logger.debug(
            "\n\t\t".join(
                ["WIERD HTTP:"] + [repr(a) for a in args]
            )
        )

    def debug(self, arg):
        return self.logger.debug(arg)

    def info(self, arg):
        return self.logger.info(arg)

    def warn(self, arg):
        return self.logger.warn(arg)

    def error(self, arg):
        return self.logger.error(arg)

    def exception(self, arg=None):
        return self.logger.exception(arg)
