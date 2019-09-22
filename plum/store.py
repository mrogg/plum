"""Store conversations and transactions in the database.

"""

import sys, code

import MySQLdb

from plum import sslstripper, httpassembler, tdsassembler, util


def escape_one(arg):
    """Return as string escaped for MySQL. 

    ...but let int or float pass through.
    """
    if isinstance(arg, (int, float)):
        return arg
    else:
        return MySQLdb.escape_string(str(arg))


def escape(*args):
    """Escape characters for safe SQL."""
    return tuple(escape_one(a) for a in args)


class ConversationStore:
    """Store conversations given."""

    def __init__(self, cfg, log):
        """Init with database cursor."""
        self.cfg = cfg
        self.log = log

        db_props = dict([(k,v) for (k,v) in cfg.items('db')
                         if k in "hostdbuserpasswd"])
        self.cursor = MySQLdb.connect(**db_props).cursor()

        self.http_assembler = httpassembler.HTTPAssembler(cfg, log)
        self.tds_assembler = tdsassembler.TDSAssembler(cfg, log)
        self.ssl_stripper = sslstripper.SSLStripper(cfg, log)

        self.http_enabled = self.cfg.getboolean('http', 'enabled')
        self.tds_enabled = self.cfg.getboolean('tds', 'enabled')
        self.ssl_enabled = self.cfg.getboolean('ssl', 'enabled')

        if self.http_enabled:
            http_ports = self.cfg.get('http', 'ports').split(',')
            self.http_ports = [int(p.strip()) for p in http_ports]
        else:
            self.http_ports = ()
        if self.tds_enabled:
            tds_ports = self.cfg.get('tds', 'ports').split(',')
            self.tds_ports = [int(p.strip()) for p in tds_ports]
        else:
            self.tds_ports = ()
        if self.ssl_enabled:
            ssl_ports = self.cfg.get('ssl', 'ports').split(',')
            self.ssl_ports = [int(p.strip()) for p in ssl_ports]

    def close(self):
        """Close database connection."""
        self.cursor.connection.close()

    @staticmethod
    def insert_conversation_sql(convo):
        """Generate SQL to insert the given conversation."""
        return """
        insert into tcp_conversations (
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            start_timestamp,
            end_timestamp,
            bytes_in,
            bytes_out,
            total_bytes,
            server_latency,
            client_latency,
            packets,
            start_position,
            retransmits_in,
            lost_packets_in,
            retransmits_out,
            lost_packets_out
        ) values (
            INET_ATON('%s'),
            %s,
            INET_ATON('%s'),
            %s,
            %f,
            %f,
            %s,
            %s,
            %s,
            %f,
            %f,
            %s,
            %s,
            %i,
            %i,
            %i,
            %i
        );
        """ % escape(
            convo['src_ip'],
            convo['src_port'],
            convo['dst_ip'],
            convo['dst_port'],
            convo['start_ts'],
            convo['end_ts'],
            convo['in_bytes'],
            convo['out_bytes'],
            convo['bytes'],
            convo['syn_ack_diff'],
            convo['latency'],
            convo['pkt_cnt'],
            convo['start_pos'],
            (convo['in_retran'] and 1 or 0),
            (convo['in_lost'] and 1 or 0),
            (convo['out_retran'] and 1 or 0),
            (convo['out_lost'] and 1 or 0),
        )

    @staticmethod
    def insert_transaction_sql(convo_id,
                               method,
                               host,
                               status,
                               url,
                               ct,
                               rsp_time,
                               in_time,
                               session_id):
        """Generate SQL to insert the given transaction."""
        return """
        insert into http_transactions (
            conversation_id,
            method,
            host,
            status,
            url,
            content_type,
            response_time,
            request_timestamp,
            session_id
        ) values (
            %s,
            '%s',
            '%s',
            %s,
            '%s',
            '%s',
            %f,
            %f,
            '%s'
        )
        """ % escape(
            convo_id,
            method,
            host,
            status,
            url,
            ct,
            rsp_time,
            in_time,
            session_id
        )

    @staticmethod
    def insert_query_sql(convo_id,
                         statement_type,
                         query,
                         response_time,
                         first_timestamp):
        """Generate SQL to insert the given transaction."""
        uquery = unicode(query, errors='replace')
        query = uquery.encode('ascii', 'replace')
        if statement_type not in ('SELECT','INSERT','UPDATE','DELETE'):
            pass #TODO: deal with unexpected statement types
        return """
        insert into sql_queries (
            conversation_id,
            statement_type,
            query_text,
            response_time,
            first_timestamp
        ) values (
            %s,
            '%s',
            '%s',
            %f,
            %f
        )
        """ % escape(
            convo_id,
            statement_type,
            query,
            response_time,
            first_timestamp
        )

    def store_conversation_info(self, convo):
        """Store conversation info, like the name says."""
        sql = self.insert_conversation_sql(convo)
        self.cursor.execute(sql)
        convo['id'] = self.cursor.lastrowid

    def store_transaction_info(self, 
                               convo, 
                               in_unit, 
                               out_unit, 
                               in_timeline, 
                               out_timeline):
        """Store transaction info, duh."""
        # Gather up a few specific data and write to the database.
        in_time = util.pdu_time(in_unit['pkt_position'],
                                convo['in_borders'],
                                in_timeline)

        # Add in_time to req timestamps
        convo['req_tss'].append(in_time)

        out_time = util.pdu_time(out_unit['pkt_position'],
                                 convo['out_borders'],
                                 out_timeline)
        response_time = out_time - in_time
        if response_time < 0:
            self.log.negative_response_time(in_time, out_time, convo)
        method, url, rest = in_unit['data'].split(' ', 2); del rest
        content_type = out_unit['headers']\
                           .get('content-type', '').lower()
        status_code = out_unit['data'].split(' ', 2)[1]
        host = in_unit['headers'].get('host', '').lower()
        sql = self.insert_transaction_sql(convo['id'],
                                          method,
                                          host,
                                          status_code,
                                          url,
                                          content_type,
                                          response_time,
                                          in_time,
                                          in_unit['session_id'])
        self.cursor.execute(sql)

    def store_query_info(self, 
                         convo, 
                         in_unit, 
                         out_unit, 
                         in_timeline, 
                         out_timeline):
        """Store transaction info, duh."""
        # Gather up a few specific data and write to the database.
        in_time = util.pdu_time(in_unit['pkt_position'],
                                convo['in_borders'],
                                in_timeline)

        # Add in_time to req timestamps
        convo['req_tss'].append(in_time)

        out_time = util.pdu_time(out_unit['pkt_position'],
                                 convo['out_borders'],
                                 out_timeline)
        response_time = out_time - in_time
        if response_time < 0:
            #TODO: Does this work for queries?
            self.log.negative_response_time(in_time, out_time, convo)
        sql = self.insert_query_sql(convo['id'],
                                    in_unit['statement_type'],
                                    in_unit['data'].strip(),
                                    response_time,
                                    in_time)
        self.cursor.execute(sql)

    def store_mtbr(self, convo):
        """Store the mean time between requests in conversation"""
        if len(convo['req_tss']) > 1:
            sum = 0
            prev_ts = convo['req_tss'][0]
            for ts in convo['req_tss']:
                sum = sum + (ts - prev_ts)
                prev_ts = ts
            
            mtbr = float(sum) / (len(convo['req_tss']) - 1)
             
            sql = """
            update tcp_conversations
            set mtbr = %f
            where id = %s 
            """ % (mtbr, convo['id'])

            self.cursor.execute(sql)
        else:
            pass

    def store(self, convo):
        """Store conversation."""
        # Syn/Ack Diff
        if convo.get('syn_ack_diff') is None:
            # TODO: Log the heck out of this so we can grow 
            #       from the exception cases.
            self.log.error(
                'No syn_ack_diff. Src Port: %s, Src IP: %s, Dst IP: %s' 
                 % (convo['src_port'],
                    convo['src_ip'],
                    convo['dst_ip'],))
            self.log.raw_packets(convo['in_pkts'] + convo['out_pkts'])
            del convo
            return

        self.store_conversation_info(convo)

        # Add PDUs to convo.
        # I thought about if this should be moved but decided that it
        # is perfect where it is because it does everything it can 
        # before making the data structure heavier. Nice and lazy.

        # If retransmits or lost packets, don't parse for pdus
        if convo['in_retran'] or convo['in_lost'] or \
            convo['out_retran'] or convo['out_lost']:
            
            self.log.error(
                'Lost or Retran: %s %s %s %s %s %s' 
                % (convo['src_ip'],
                   convo['src_port'],
                   convo['in_retran'],
                   convo['in_lost'],
                   convo['out_retran'],
                   convo['out_lost']))
            #all_pkts = convo['in_pkts'] + convo['out_pkts']
            #all_pkts.sort(key=lambda i: (i['ts']))
            #self.log.raw_packets(all_pkts)
            del convo
            return

        try:
            self.assemble_pdus(convo)
        except Exception, e:
            self.log.warn("PDU Assembly Error")
            self.log.exception(e)
            return
        # If number of responses doesn't match number of requests 
        # then don't store any transactions from this conversation
        # TODO: Follow sequence numbers and do more better skipping
        # so don't have to throw away all transactions in a conversation
        if len(convo['in_pdus']) != len(convo['out_pdus']):
            #print len(convo['in_pdus']), len(convo['out_pdus']), convo['src_port']
            #print "in pdus:"
            #for pdu in convo['in_pdus']:
            #    uquery = unicode(pdu['data'], errors='replace')
            #    query = uquery.encode('ascii', 'replace')
            #    print pdu['first_header'], query
            #print "out pdus:"
            #for pdu in convo['out_pdus']:
            #    print pdu['first_header']
            
            #self.log.error(
            #    'PDU Count Mismatch. Src Port: %s, Src IP: %s, Dst IP: %s' 
            #     % (convo['src_port'],
            #        convo['src_ip'],
            #        convo['dst_ip'],))
            #self.log.raw_packets(convo['packets'])
            #self.log.missing_packets(convo)
            del convo
            return

        in_timeline = convo['in_timeline']
        out_timeline = convo['out_timeline']

        # Setup for req_ts list for conv
        convo['req_tss'] = []

        dst_port = convo['dst_port']
        if dst_port in self.http_ports:
            pdu_store_func = self.store_transaction_info
        elif dst_port in self.tds_ports:
            pdu_store_func = self.store_query_info
        else:
            #TODO: I guess this should do more logging.
            pdu_store_func = lambda a, b, c, d, e: a

        
        # Loop through the incoming PDUs and get the cooresponding 
        # out_pdu in the same position in the list.
        for pos, unit in enumerate(convo['in_pdus']):
            pdu_store_func(convo,
                           unit,
                           convo['out_pdus'][pos], # out PDU
                           in_timeline,
                           out_timeline)

        self.store_mtbr(convo)

        del convo
        del in_timeline
        del out_timeline

    def assemble_pdus(self, convo):
        """Use the right assembler after stripping if needed."""
        dst_port = convo['dst_port']
        if dst_port in self.http_ports:
            assembler = self.http_assembler
        elif dst_port in self.tds_ports:
            assembler = self.tds_assembler
        else:
            assembler = lambda a, b, c, d, e: e
        if self.ssl_enabled and dst_port in self.ssl_ports:
            return assembler(*self.stripper(convo))
        else:
            return assembler(convo['in_stream'], 
                             convo['in_borders'][:],
                             convo['out_stream'], 
                             convo['out_borders'][:],
                             convo)

