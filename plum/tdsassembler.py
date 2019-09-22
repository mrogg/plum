"""Assemble TDS PDUs from stream of bytes."""


import struct


def uint16(bytes):
    """Parse a two byte bigendian integer."""
    return struct.unpack(">H", bytes)[0]


class TDSAssembler(object):
    """."""

    def __init__(self, cfg, log):
        """."""
        self.cfg = cfg
        self.log = log

    def update_borders(self, borders, data_end):
        """Lose the border entries that we have already parsed past."""
        for border in [b for b in borders if b < data_end]:
            borders.remove(border)

    def payload(self, unit, header, stream, borders, start,convo):
        if borders:
            del borders[0]
        end = start + 8 + header['size']
        data = stream[start+8:end]
        if borders and end < borders[0]:
            borders.insert(0, end)
        if header['last'] or not stream[end:]:
            return data
        else:
            next_header = self.parse_header(stream[end:end+8])
            #if header['type'] != next_header['type']\
            #        and convo['src_port'] == 1:
            #    print header, next_header
            #    return data
            return data + self.payload(unit, next_header, 
                                       stream, borders, end,convo)
            
    def parse_query(self, unit, header, stream, borders, start,convo):
        data = self.payload(unit, header, stream, borders, start,convo)
        unit['data'] = data
        #if convo['src_port'] == 51671:
        #    print header
        #    print data
        #if not data and None:
        #    print repr(data), header
        #    print convo.keys()
        #    print convo['src_ip'], convo['dst_ip'], convo['src_port']
        if data:
            statement_type = unit['data'].strip().split(None, 1)[0]
            unit['statement_type'] = statement_type.upper()
        else:
            unit['statement_type'] = 'EMPTY'
        return data

    def parse_response(self, unit, header, stream, borders, start,convo):
        data = self.payload(unit, header, stream, borders, start,convo)
        unit['data'] = data
        unit['response_type'] = data and ord(data[0]) or -1
        return data

    #def parse_login(self, unit, header, stream, borders, start,convo):
    #    data = self.payload(unit, header, stream, borders, start,convo)
    #    unit['data'] = data
    #    return data

    def parse_default(self, unit, header, stream, borders, start,convo):
        """Just ignore any packet that is not query or response.""" 
        return self.payload(unit, header, stream, borders, start,convo)

    def choose_parser(self, header):
        """Choose and return a specialized parser."""
        if header['type'] in (0x01, 0x0f):
            return self.parse_query
        elif header['type'] == 0x04:
            return self.parse_response
        #elif header['type'] in (0x02, 0x10):
        #    return self.parse_login
        else:
            return self.parse_default

    def parse_header(self, bytes):
        header = {'type': ord(bytes[0]),
                  'last': ord(bytes[1]),
                  'size': uint16(bytes[2:4])}
        return header

    def parse_stream(self, stream, borders,convo, units=None):
        """Given a stream of bytes parse out all PDUs, recursively.

        Parses headers, then dispatches to the appropriate specialized 
        parser.
        Note: This is destructive to borders.
        """
        # Default units.
        if units is None:
            units = []
        # Bail if 0 len stream.
        if len(stream) == 0:
            return units
        
        # Parse the header in order to dispatch.
        start = borders[0]
        if not stream[start:]:
            return units
        header = self.parse_header(stream[start:start+8])
        parser = self.choose_parser(header)
        unit = dict(pkt_position=start, first_header=header)
        parser(unit, header, stream, borders, start, convo)

        if (header['type'] in (0x01, 0x0f, 0x04)#, 0x02, 0x10) 
            and unit.get('response_type') in (None, 253, 160)
            and not header['last'] == 51):
            units.append(unit)

        # Recurse, if there are more bytes to parse in stream.
        if len(borders) == 0:
            return units
        else:
            return self.parse_stream(stream, borders,convo, units)

    def __call__(self, in_stream, in_borders, 
                 out_stream, out_borders, convo):
        """Put http packets back together.

        Note: This is not destructive to in_borders and out_borders.
        """
        convo['in_pdus'] = self.parse_stream(in_stream, in_borders,convo)
        convo['out_pdus'] = self.parse_stream(out_stream, out_borders,convo)
        return convo

