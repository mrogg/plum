"""Assemble HTTP PDUs from stream of bytes.

"""

from Cookie import SimpleCookie


class HTTPAssembler(object):
    """."""

    def __init__(self, cfg, log):
        """."""
        self.cfg = cfg
        self.log = log


    # Utilities:

    def parse_headers(self, data):
        """Parse HTTP headers."""
        #TODO: Do we need to do something a little more sophisticated?
        headers = {}
        for header_line in data.split('\r\n'):
            header_line = header_line.split(': ', 1)
            if len(header_line) == 2:
                #TODO: Is it a good idea to just lower() it all like that?
                #headers[header_line[0].lower()] \
                #    = header_line[1].strip().lower()

                key = header_line[0].lower()
                value = header_line[1].strip()
                if key in headers:
                    current = headers[key]
                    if not isinstance(current, list):
                        headers[key] = [current]
                    headers[key].append(value)
                else:
                    headers[key] = value
            else:
                pass
                #TODO: Log ill-formed header...
        return headers

    def pipe_borders(self, stream, borders, data_end):
        """Add borders for pipelined PDUs to borders list.

        This way, when parse_stream recurses, it picks up parsing 
        with the next PDU in the pipeline, instead of the first one 
        in the next TCP packet.
        """
        # Check if Pipelined Response
        if (data_end != len(stream) and data_end not in borders):
            # I put these on one line to emphasize that they are
            # intended as one atomic operation.
            borders.insert(0, data_end); borders.sort()

    def update_borders(self, borders, data_end):
        """Lose the border entries that we have already parsed past."""
        for border in [b for b in borders if b < data_end]:
            borders.remove(border)


    # Specialized parsers:
    # These usually fall through in source order (the order listed).
    # IOW, the first one of these that applies is usually the one used.
    # See `parse_stream` method below for details.

    def parse_chunked(self, unit, headers, stream, borders, data_start):
        """Parse chuck encoded PDU."""
        # We are making the assumption that new responses start on
        # packet boundaries for some reason. 
        # TODO: Check if responses could come right after other responses 
        # and not at packet boundaries.
        # TODO: Check if headers, or "trailers", can come in between chunks.
        full_unit = ''
        header = stream[borders[0]:data_start]
        full_unit += header

        # assemble the chunks
        # TODO: Should we be losing the \r\n between chunks? (We are.)
        # If so, what other decoding should we be doing?
        chunk_length = None
        while chunk_length != 0:
            chunk_length = int(stream[data_start:].split('\r\n', 1)[0], 16)
            chunk_start = data_start + stream[data_start:].find('\r\n') + 2
            chunk_end = chunk_start + chunk_length
            full_unit += stream[chunk_start:chunk_end]
            self.update_borders(borders, chunk_end)
            data_start = chunk_end + 2 # 2 because of \r\n

        unit['data'] = full_unit

    def parse_with_content_length(self, unit, headers, 
                                  stream, borders, data_start):
        """Parse PDU when Content-length header is present (which is nice)."""
        data_end = int(headers['content-length']) + data_start
        unit['data'] = stream[borders[0]:data_end]
        self.pipe_borders(stream, borders, data_end)
        self.update_borders(borders, data_end)

    def parse_with_connection_close(self, unit, headers, 
                                    stream, borders, data_start):
        """Parse PDU when Connection header is set to 'close'."""
        # Connection set to close so no more data will be sent in this
        # conversation in this direction
        unit['data'] = stream[borders[0]:]
        borders[:] = ()

    def parse_GET(self, unit, headers, stream, borders, data_start):
        """Parse PDU for GET request."""
        # No way to tell how far to read but if this is a GET
        # then read up until end of header
        unit['data'] = stream[borders[0]:data_start - 4]
        self.pipe_borders(stream, borders, data_start)
        self.update_borders(borders, data_start)

    def parse_default(self, unit, headers, stream, borders, data_start):
        """Parse PDU when no other parser applies. 

        Just put the rest of the packet in unit['data'], which is lame.
        """
        # No length given so everything is in one packet.
        # Crap, then how do I know when it stops? Well,
        # I guess I'll have to check the timeline 
        # packet boundaries packet breaks 
        # TODO: Better logging so that we can grow this thing from the
        # exception cases.
        #self.log.weird_http(unit, headers, stream, borders, data_start)
        if len(borders) > 1:
            unit['data'] = stream[borders[0]:borders[1]]
        elif len(borders) == 1:
            unit['data'] = stream[borders[0]:]
        else:
            self.log.warn('Parsing Error: 0 len borders!')

        # TODO: Decide if we need data and what to do with it.
        #del unit['data']
        del borders[0]


    # Parse HTTP headers and dispatch:

    def choose_parser(self, headers, stream, borders):
        """Choose and return a specialized parser."""
        if headers.get('transfer-encoding') is not None:
            if headers['transfer-encoding'].lower() == 'chunked':
                return self.parse_chunked
            else:
                self.log.debug(
                    'Protocol Error: unknown transfer-encoding: %s'
                     % repr(headers['transfer-encoding'])
                )
        elif headers.get('content-length') is not None:
            return self.parse_with_content_length
        elif headers.get('connection', '').strip().lower() == 'close':
            return self.parse_with_connection_close
        elif stream[borders[0]:borders[0] + 3].upper() == 'GET':
            return self.parse_GET
        else:
            return self.parse_default

    def get_session_id(self, headers):
        """Try to extract a session id from the headers."""
        session_keys = self.cfg.get('http', 'session_keys')
        session_keys = [s.strip() for s in session_keys.split(',')]
        if 'cookie' in headers:
            cookies = headers['cookie']
            if not isinstance(cookies, list):
                cookies = [cookies]
            for cookie_string in cookies:
                cookie = SimpleCookie()
                cookie.load(cookie_string)
                for session_key in session_keys:
                    if session_key in cookie:
                        return cookie[session_key].value

    def parse_stream(self, stream, borders, units=None):
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

        # Parse the headers and status line in order to dispatch.
        end_of_head = stream[borders[0]:].find('\r\n\r\n') + borders[0]
        data_start = end_of_head + 4 
        headers = self.parse_headers(stream[borders[0]:end_of_head])
        del end_of_head

        parser = self.choose_parser(headers, stream, borders)
        unit = dict(pkt_position=borders[0])
        unit['session_id'] = self.get_session_id(headers)
        parser(unit, headers, stream, borders, data_start)

        unit['headers'] = headers
        try:
            status = unit['data'].split(' ', 2)[1]
            if status != '100':
                units.append(unit)
        except Exception, e:
            self.log.warn("Doesn't look like HTTP to me, Mate.")
            self.log.exception(e)

        # Recurse, if there are more bytes to parse in stream.
        if len(borders) == 0:
            return units
        else:
            return self.parse_stream(stream, borders, units)


    # Main interface:

    def __call__(self, in_stream, in_borders, 
                 out_stream, out_borders, convo):
        """Put http packets back together.

        Note: This is not destructive to in_borders and out_borders.
        """
        convo['in_pdus'] = self.parse_stream(in_stream, in_borders)
        convo['out_pdus'] = self.parse_stream(out_stream, out_borders)
        return convo


