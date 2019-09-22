"""Mainly, this module offers the SSLStripper class for decoding SSL traffic."""


import struct

# TODO: This is a temporary hack. FIX ME!
try:
    from tlslite.utils.keyfactory import parsePEMKey
    from tlslite.mathtls import PRF, PRF_SSL
    from tlslite.utils.compat import createByteArraySequence as byteArray
    from tlslite.utils.OpenSSL_AES import OpenSSL_AES
except:
    pass

from plum import util


cipher_suites = {
    (0x00, 0x35): 'TLS_RSA_WITH_AES_256_CBC_SHA',
    (0x00, 0x2f): 'TLS_RSA_WITH_AES_128_CBC_SHA',
}


def aes_decryptor(ssl_convo, record, source='client'):
    """Decrypt via aes."""
    # I think we need to reset the iv to the last encrypted block for CBC.
    # We are doing this in all cases because I heard that it is all CBC.
    # We will see. :) (Should this even be in the individual decryptor?)
    iv_size = int(ssl_convo.suite_props['iv_size'])
    if source == 'client':
        key = ssl_convo.client_key
        iv = ssl_convo.client_iv
        ssl_convo.client_iv = byteArray(record.body[-iv_size:])
    else:
        key = ssl_convo.server_key
        iv = ssl_convo.server_iv
        ssl_convo.server_iv = byteArray(record.body[-iv_size:])
    decryptor = OpenSSL_AES(key, 2, iv) # 2 = mode CBC
    #len_decrypted_iv = len(decryptor.decrypt(iv.tostring()))
    return decryptor.decrypt(record.body)
    

# Block size should be IV size.
suite_props = {
    'TLS_RSA_WITH_AES_256_CBC_SHA': 
    dict(
        key_exchange='RSA',
        mode='CBC',
        iv_size='16',
        key_size='32',
        hash='SHA',
        decryptor=aes_decryptor,
    ),
    'TLS_RSA_WITH_AES_128_CBC_SHA':
    dict(
        key_exchange='RSA',
        mode='CBC',
        iv_size='16',
        key_size='16',
        hash='SHA',
        decryptor=aes_decryptor,
    ),
}


record_types = {
    20: 'change_cipher_spec',
    21: 'alert',
    22: 'handshake',
    23: 'application_data'
}


handshake_types = {
    0: 'hello_request',
    1: 'client_hello',
    2: 'server_hello',
    11: 'certificate',
    12: 'server_key_exchange',
    13: 'certificate_request',
    14: 'server_hello_done',
    15: 'certificate_verify',
    16: 'client_key_exchange',
    20: 'finished'
}


def uint8(byte):
    """Parse a one byte bigendian integer."""
    return struct.unpack(">H", "\0"+byte)[0]


def uint16(bytes):
    """Parse a two byte bigendian integer."""
    return struct.unpack(">H", bytes)[0]


def uint24(bytes):
    """Parse a three byte bigendian integer."""
    return struct.unpack(">L", "\0"+bytes)[0]


def update_borders(borders, data_end):
    """Lose the border entries that we have already parsed past."""
    for border in [b for b in borders if b < data_end]:
        borders.remove(border)
    if (not borders) or (borders[0] > data_end):
        borders.insert(0, data_end)


class HandshakeMessage(object):
    """."""
    
    def __init__(self, ssl_convo, record, bytes, cfg, log):
        """."""
        self.cfg = cfg
        self.log = log
        type_int = uint8(bytes[0])
        #if type_int > 20:
            #self.length = 48
            #self.type = 'client_key_exchange'
            #return hs_parse_client_key_exchange(ssl_convo, record, self, bytes)
        #    self.type = 'unknown'
        #    self.length = 44
        #    return self.do_nothing(ssl_convo, record, self, bytes)

        self.type = handshake_types.get(uint8(bytes[0]), 'finished')
        self.length = uint24(bytes[1:4])
        print self.type, self.length
        #print "hs length", self.handshake_length
        #if self.handshake_length == 0: 
            # Guess handshake length cause bad implementation
            #print "guessing length"
            #self.handshake_length = len(bytes) - 4
        parse = self.handshake_parsers[self.type]
        parse(self, ssl_convo, record, self, bytes[4:self.length + 4])

    # Handshake Parsers:

    def do_nothing(self, ssl_convo, record, handshake, bytes):
        """Do nothing, just like you might guess."""
        pass

    def hs_parse_client_hello(self, ssl_convo, record, handshake, bytes):
        """Parse ClientHello handshake message."""
        ssl_convo.client_version = uint8(bytes[0]), uint8(bytes[1])
        ssl_convo.client_random = byteArray(bytes[2:34])

    def hs_parse_server_hello(self, ssl_convo, record, handshake, bytes):
        """Parse ServerHello handshake message."""
        ssl_convo.version = uint8(bytes[0]), uint8(bytes[1])
        # TODO: Log unexpected versions.
        ssl_convo.server_random = byteArray(bytes[2:34])
        session_id_end = uint8(bytes[34]) + 35
        ssl_convo.session_id = bytes[35:session_id_end]
        suite = (uint8(bytes[session_id_end]), uint8(bytes[session_id_end + 1]))
        # TODO: Log unexected suites.
        ssl_convo.cipher_suite = cipher_suites[suite]
        ssl_convo.suite_props = suite_props[ssl_convo.cipher_suite]

    def hs_parse_client_key_exchange(self, ssl_convo, record, handshake, bytes):
        """Parse ClientKeyExchange handshake message."""
        # TODO: Where the heck did these 2 extra bytes come from?
        ssl_convo.encrypted_pre_master_secret = bytes[2:]
        if ssl_convo.suite_props['key_exchange'] == 'RSA':
            private_key = self.cfg.get('ssl', 'private_key')
            rsa_key = parsePEMKey(open(private_key).read())
            array = byteArray(bytes[2:])
            ssl_convo.pre_master_secret = rsa_key.decrypt(array)
            assert len(ssl_convo.pre_master_secret) == 48
        else:
            pass # TODO: Something. Logging.

    def hs_finished(self, ssl_convo, record, handshake, bytes):
        """Parse a finished message."""
        self.body = bytes

    handshake_parsers = {
        'hello_request': do_nothing,
        'client_hello': hs_parse_client_hello,
        'server_hello': hs_parse_server_hello,
        'certificate': do_nothing,
        'server_key_exchange': do_nothing,
        'certificate_request': do_nothing,
        'server_hello_done': do_nothing,
        'certificate_verify': do_nothing,
        'client_key_exchange': hs_parse_client_key_exchange,
        'finished': hs_finished,
        'unknown': do_nothing, # TODO: This should log, I guess.
    }


class SSLRecord(object):
    """Represent an SSL Record."""
    
    def __init__(self, stream, borders, timeline, cfg, log):
        """Parse the header but leave payload untouched."""
        self.handshakes = []
        self.stream = stream
        self.start = borders[0]
        print "start", self.start, borders
        self.timestamp = util.pdu_time(self.start, borders, timeline)
        self.cfg = cfg
        self.log = log

        first_byte = self.pos(0)
        self.type = record_types.get(uint8(first_byte), 'unknown')
        if self.type == 'unknown':
            # Guess that we have SSLv2 client hello here.
            self.version = (2, 0)
            first_byte = ord(first_byte)
            is_padded = (first_byte & 0x39) != 0
            #is_escape = (first_byte & 0x40) != 0
            self.length = (first_byte & 0x7f) << 8 | ord(self.pos(1))
            #print self.length, is_padded #, is_escape
            header_len = 2; padding = 0
            if is_padded:
                padding = ord(self.pos(2))
                header_len = 3
            self.body = self.range(header_len, header_len + self.length)
            update_borders(borders, 
                           self.start + self.length 
                            + padding + header_len)
            '''
            if len(borders) > 1:
                borders.pop(0)
                self.start = borders[0]
                type_id = uint8(self.pos(0))
                self.type = record_types.get(type_id, 'unknown')
                print "retyped", self.type
            '''
        else:
            self.version = uint8(self.pos(1)), uint8(self.pos(2))
            self.length = uint16(self.range(3, 5))

            self.body = self.range(5, self.length + 5)

            update_borders(borders, self.start + self.length + 5)

    def pos(self, num):
        """Byte from source stream at given position relative to self.start."""
        return self.stream[self.start + num]

    def range(self, start, end):
        """Bytes from source stream between positions relative to self.start."""
        return self.stream[self.start + start:self.start + end]

    def has_handshake_type(self, type_name):
        """Do any of the handshakes in this record have this type?"""
        for shake in self.handshakes:
            if shake.type == type_name:
                return True
        else:
            return False

    def parse_handshakes(self, ssl_convo):
        """Parse handshake protocol messages encapsulated in this record."""
        parsed_bytes = 0
        total_bytes = len(self.body)
        while parsed_bytes < total_bytes:
            shake = HandshakeMessage(
                ssl_convo, 
                self, 
                self.body[parsed_bytes:],
                self.cfg,
                self.log)
            parsed_bytes += (shake.length + 4) # 4 byte header
            self.handshakes.append(shake)

''' 
        type_int = uint8(self.body[0])
        if type_int > 20:
            print len(self.body)
        self.handshake_type = handshake_types.get(uint8(self.body[0]), 'finished')
        self.handshake_length = uint24(self.body[1:4])
        #print "hs length", self.handshake_length
        #if self.handshake_length == 0: # Guess handshake length cause bad implementation
            #print "guessing length"
            #self.handshake_length = len(self.body) - 4
        parse = handshake_parsers[self.handshake_type]
        return parse(ssl_convo, self, self.body[4:self.handshake_length + 4])
'''


class SSLConvo(object):
    """Represent an encrypted conversation."""

    def __init__(self, convo, cfg, log):
        """Simple init, copies borders so that they can be processed."""
        self.convo = convo
        self.cfg = cfg
        self.log = log
        self.in_stream = convo['in_stream']
        self.in_borders = convo['in_borders'][:]
        self.out_stream = convo['out_stream'] 
        self.out_borders = convo['out_borders'][:]

    def parse_handshake(self, stripper):
        """Parse the info we need out of the handshake protocol."""
        # Drive handshake from here.

        client_hello = self.parse_record_in()
        client_hello.parse_handshakes(self)
        server_hello = self.parse_record_out()
        server_hello.parse_handshakes(self)
        # TODO: Test that we have right values or error?

        if self.session_id in stripper.sessions:
            session = stripper.sessions[self.session_id]
            self.master_secret = session['master_secret']
        else:
            while 1:
                key_exchange = self.parse_record_in()
                if key_exchange is None:
                    break
                if key_exchange.type != 'handshake':
                    continue
                key_exchange.parse_handshakes(self)
                if not key_exchange.has_handshake_type('client_key_exchange'):
                    continue
                break
            while 1:
                finished = self.parse_record_in()
                if finished is None:
                    break
                if finished.type != 'handshake':
                    continue
                finished.parse_handshakes(self)
                for shake in finished.handshakes:
                    print 'shake type', shake.type
                if not finished.has_handshake_type('finished'):
                    continue
                for shake in finished.handshakes:
                    if shake.type == 'finished':
                        print "client finished"
                        self.client_iv = shake.body[-16:]
                break
            while 1:
                finished = self.parse_record_out()
                if finished is None:
                    break
                if finished.type != 'handshake':
                    continue
                finished.parse_handshakes(self)
                for shake in finished.handshakes:
                    print 'out shake type', shake.type
                if not finished.has_handshake_type('finished'):
                    continue
                for shake in finished.handshakes:
                    if shake.type == 'finished':
                        print "server finished"
                        self.server_iv = shake.body[-16:]
                break
            self.derive_master_secret()
            session = stripper.sessions.setdefault(self.session_id, {})
            session['master_secret'] = self.master_secret

        # TODO: Test that we have right values or error?

        self.derive_keys()


    def derive_master_secret(self):
        """Derive master secret from pre-master secret.

        You need to have parsed the key exchange before doing this.
        """
        props = self.suite_props
        seed = self.client_random + self.server_random
        if props['key_exchange'] == 'RSA' and self.version == (3,1):
            self.master_secret = PRF(self.pre_master_secret,
                                     byteArray("master secret"),
                                     seed,
                                     48)
        elif props['key_exchange'] == 'RSA' and self.version == (3,0):
            self.master_secret = PRF_SSL(self.pre_master_secret, seed, 48)
        else:
            pass # TODO: Log this.

    def derive_keys(self):
        """Generate the needed key material."""
        props = self.suite_props
        hash_size = (props['hash'] == 'SHA' and 20 or 16)
        key_block_size = (int(props['iv_size']) 
                          + int(props['key_size']) 
                          + hash_size) * 2
        if props['key_exchange'] == 'RSA' and self.version == (3,1):
            key_block = PRF(self.master_secret,
                            byteArray("key expansion"),
                            self.server_random + self.client_random,
                            key_block_size)
        elif props['key_exchange'] == 'RSA' and self.version == (3,0):
            key_block = PRF_SSL(self.master_secret,
                                self.server_random + self.client_random,
                                key_block_size)
        else:
            pass # TODO: Log This
        self.slice_key_block(key_block)
        # Export-cipher crippling stuff here

    def slice_key_block(self, key_block):
        """Slice and dice the parts out of the key material."""
        props = self.suite_props
        if props['hash'] == 'SHA':
            key_block = key_block[40:]
        else:
            key_block = key_block[32:]

        key_size_int = int(props['key_size'])
        self.client_key = key_block[:key_size_int]
        key_block = key_block[key_size_int:]
        self.server_key = key_block[:key_size_int]
        key_block = key_block[key_size_int:]

        #iv_size_int = int(props['iv_size'])
        #self.client_iv = key_block[:iv_size_int]
        #key_block = key_block[iv_size_int:]
        #self.server_iv = key_block[:iv_size_int]
        #key_block = key_block[iv_size_int:]

    def decrypt_in_stream(self):
        """Parse application payload out the in stream."""
        borders = [0]; stream = []
        ssl_timeline = {0:util.pdu_time(0, 
                                        borders, 
                                        self.convo['in_timeline'])}
        props = self.suite_props
        decrypt = props['decryptor']
        hash_size = (props['hash'] == 'SHA' and 20 or 16)
        last_timestamp = None
        while 1:
            record = self.parse_record_in()
            if record is None:
                break
            if record.type != 'application_data':
                continue
            app_data = decrypt(self, record, source='client')
            padding_len = uint8(app_data[-1]) + 1
            app_data = app_data[:-(hash_size + padding_len)]
            new_border = borders[-1] + len(app_data)
            borders.append(new_border)
            if record.timestamp is not None:
                last_timestamp = record.timestamp 
            ssl_timeline[new_border] = last_timestamp
            stream.append(app_data)
        self.convo['in_timeline'] = ssl_timeline
        borders.pop()
        return "".join(stream), borders

    def decrypt_out_stream(self):
        """Parse application payload out of the out stream."""
        borders = [0]; stream = []
        ssl_timeline = {0:util.pdu_time(0, borders, self.convo['out_timeline'])}
        props = self.suite_props
        decrypt = props['decryptor']
        hash_size = (props['hash'] == 'SHA' and 20 or 16)
        last_timestamp = None
        while 1:
            record = self.parse_record_out()
            if record is None:
                break
            if record.type != 'application_data':
                continue
            app_data = decrypt(self, record, source='server')
            # TODO: No padding at all if not block, I think.
            padding_len = uint8(app_data[-1]) + 1
            app_data = app_data[:-(hash_size + padding_len)]
            new_border = borders[-1] + len(app_data)
            borders.append(new_border)
            if record.timestamp is not None:
                last_timestamp = record.timestamp
            ssl_timeline[new_border] = last_timestamp
            stream.append(app_data)
        self.convo['out_timeline'] = ssl_timeline
        borders.pop()
        return "".join(stream), borders

    def streams_and_borders(self):
        """Decrypted streams and borders to pass to the next layer up."""
        # TODO:
        # Use self.suite_prefs to utilize the proper key material and
        # the proper library. Now we just build up prefs and lib calling
        # fuctions to use with them and we should be set. I think...
        in_stream, in_borders = self.decrypt_in_stream()
        out_stream, out_borders = self.decrypt_out_stream()
        return (in_stream, in_borders, 
                out_stream, out_borders, 
                self.convo)

    def parse_record_in(self):
        """Parse the next record off the in-bound stream."""
        if len(self.in_borders) > 1:
            return SSLRecord(
                self.in_stream, 
                self.in_borders, 
                self.convo['in_timeline'],
                self.cfg, 
                self.log
            )

    def parse_record_out(self):
        """Parse the next record off the out-bound stream."""
        if len(self.out_borders) > 1:
            return SSLRecord(
                self.out_stream, 
                self.out_borders,
                self.convo['out_timeline'],
                self.cfg, 
                self.log
            )


class SSLStripper(object):
    """Manages the decryption of encrypted traffic."""

    def __init__(self, cfg, log):
        """Simple init, creates a sessions dict."""
        # Obviously this needs to be managed or become a ringbuffer
        # or similar self-managing structure.
        self.sessions = {}
        self.cfg = cfg
        self.log = log

    def __call__(self, convo):
        """Decrypt a conversation, returning streams and border."""
        ssl_convo = SSLConvo(convo, self.cfg, self.log)
        ssl_convo.parse_handshake(self)
        return ssl_convo.streams_and_borders()
