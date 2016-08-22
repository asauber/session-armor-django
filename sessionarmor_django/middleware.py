'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2015 - 2016 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt

TODO: Audit for comparison-based timing attacks
'''


import base64
import hashlib
import hmac
import logging
import time
import json
from datetime import datetime, timedelta

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import random as crypt_random
from Crypto.Util import Counter
from django.conf import settings
from django.core.cache import caches
from django.core.exceptions import PermissionDenied
from django.contrib.sessions.exceptions import InvalidSessionKey

COUNTER_BITS = 128

CLIENT_READY = 'ready'
CLIENT_SIGNED_REQUEST = 'request'

HASH_ALGO_MASKS = (
    # these hashing algorithms are in order of preference
    (1 << 2, hashlib.sha512),
    (1 << 1, hashlib.sha384),
    (1 << 0, hashlib.sha256),
    (1 << 3, lambda: hashlib.new('ripemd160')),
)

LOGGER = logging.getLogger(__name__)

SECONDS_14_DAYS = 1209600

assert len(settings.SECRET_KEY) >= AES.block_size, \
    "Django settings.SECRET_KEY must be at least {} bytes".format(
        AES.block_size)
SECRET_KEY = bytes(settings.SECRET_KEY[:AES.block_size])

DEFAULT_AUTH_HEADERS = [
    'Host',
    'User-Agent',
    'Accept',
    'Accept-Encoding',
    'Accept-Language',
    'Referer',
    'Cookie'
]

ALL_AUTH_HEADERS = [
    'Host',
    'User-Agent',
    'Accept',
    'Connection',
    'Accept-Encoding',
    'Accept-Language',
    'Referer',
    'Cookie',
    'Accept-Charset',
    'If-Modified-Since',
    'If-None-Match',
    'Range',
    'Date',
    'Authorization',
    'Cache-Control',
    'Origin',
    'Pragma',
    'DNT',
    'X-Csrf-Token',
    'Sec-WebSocket-Version',
    'Sec-WebSocket-Protocol',
    'Sec-WebSocket-Key',
    'Sec-WebSocket-Extensions',
    'TE',
    'X-Requested-With',
    'X-Forwarded-For',
    'X-Forwarded-Proto',
    'Forwarded',
    'From',
    'HTTP2-Settings',
    'Upgrade',
    'Proxy-Authorization',
    'If',
    'If-Match',
    'If-Range',
    'If-Unmodified-Since',
    'Max-Forwards',
    'Prefer',
    'Via',
    'ALPN',
    'Expect',
    'Alt-Used',
    'CalDAV-Timezones',
    'Schedule-Reply',
    'If-Schedule-Tag-Match',
    'Destination',
    'Lock-Token',
    'Timeout',
    'Ordering-Type',
    'Overwrite',
    'Position',
    'Depth',
    'SLUG',
    'Trailer',
    'MIME-Version'
]

# TODO: generate this dynamically using dict comprehension and move
# descriptions above
AUTH_HEADER_MASKS = {
    # Hostname to which the client is sending the request
    'Host': (1 << 0),

    # String indicating the software and/or hardware platform used to generate
    # the request
    'User-Agent': (1 << 1),

    # Types of media that the client would accept in a response
    'Accept': (1 << 2),

    # Desired behavior of the connection with the first remote machine
    'Connection': (1 << 3),

    # Character encodings that the client would accept in a response
    'Accept-Encoding': (1 << 4),

    # Human languages that the client would accept in a response
    'Accept-Language': (1 << 5),

    # URI that caused or enabled the client to make the request
    'Referer': (1 << 6),

    # Persistent general-purpose tokens that the client provides to the server
    'Cookie': (1 << 7),

    # Character sets that the client would accept in a response
    'Accept-Charset': (1 << 8),

    # The last modified time known by the client, response requested if
    # modified
    'If-Modified-Since': (1 << 9),

    # An entity tag. A response is requested if the entity does not match.
    'If-None-Match': (1 << 10),

    # Specifies a portion of the resource being requested
    'Range': (1 << 11),

    # Time at which a request was sent that includes body data
    'Date': (1 << 12),

    # Authentication credentials provided by the client for Basic or Digest
    # HTTP Authentication
    'Authorization': (1 << 13),

    # An indication of how the request should be treated by caching proxies
    'Cache-Control': (1 << 14),

    # A list of origins that caused the request, e.g. used by a client script
    # that has established allowable cross-origin methods via CORS
    'Origin': (1 << 15),

    # General-purpose header field, most often used with "no-cache" to request
    # a non-cached version of a resource
    'Pragma': (1 << 16),

    # Boolean indicating that the user wishes not to be tracked by the server
    'DNT': (1 << 17),

    # Nonce sent by the server to be used for Cross Site Request Forgery
    # protection
    'X-Csrf-Token': (1 << 18),

    # Version of the WebSocket protocol being used
    'Sec-WebSocket-Version': (1 << 19),

    # Used with websocket handshake to indicate what application level
    # protocols the client wishes to use
    'Sec-WebSocket-Protocol': (1 << 20),

    # Randomly generated nonce used during the Websocket handshake
    'Sec-WebSocket-Key': (1 << 21),

    # A list of registered websocket extended features that the client wishes
    # to use with a websocket connection
    'Sec-WebSocket-Extensions': (1 << 22),

    # Transfer Encodings that the user agent will accept, e.g. "deflate". Can
    # also specify that "trailers" should be used for chunked transfers
    'TE': (1 << 23),

    # Mechanism used to make the request, e.g. XMLHttpRequest
    'X-Requested-With': (1 << 24),

    # IP addres or hostname that originated the request (after travelling
    # through a proxy)
    'X-Forwarded-For': (1 << 25),

    # The original protocol used when the request was made, e.g. "https" (after
    # travelling through a proxy
    'X-Forwarded-Proto': (1 << 26),

    # Used by a proxy server to include information that would otherwise be
    # lost at lower levels in the protocol stack
    'Forwarded': (1 << 27),

    # The email address of the user making the request, most often used by
    # robots as contact information for the robot administrator
    'From': (1 << 28),

    # Settings for protocol-upgrade with an HTTP/2 capable host
    'HTTP2-Settings': (1 << 29),

    # Another protocol, to which the agent wishes to switch, e.g. HTTP/2.0
    'Upgrade': (1 << 30),

    # Credentials request by a proxy in the request chain. Consumed by the
    # first proxy requesting authentication.
    'Proxy-Authorization': (1 << 31),

    # List of conditions for a resource to meet for a response to be requested
    'If': (1 << 32),

    # An entity tag that must match the resource for a response to be requested
    'If-Match': (1 << 33),

    # Combination of If-Match and If-Unmodified-Since for a range request
    'If-Range': (1 << 34),

    # A timestamp. A response is requested if the entity has not been modified
    # since this time.
    'If-Unmodified-Since': (1 << 35),

    # An integer. Used with TRACE or OPTIONS requests to limit forwarding by
    # proxies
    'Max-Forwards': (1 << 36),

    # Preferences requested of the server, examples include: asynchronous
    # response, relative priority, response verbosity
    'Prefer': (1 << 37),

    # A list of proxies through which the request was sent
    'Via': (1 << 38),

    # Protocol stack that that the client would like to tunnel via HTTP
    'ALPN': (1 << 39),

    # Expected response from the server, usually HTTP 100 (Continue). In this
    # case the client wishes to know if a request body is acceptable before
    # sending it to the server.
    'Expect': (1 << 40),

    # Alternative host that the client selected for a request
    'Alt-Used': (1 << 41),

    # Client indicating whether or not it would like timezones on calendars
    'CalDAV-Timezones': (1 << 42),

    # A boolean, indicates if a client will attend a CalDAV calendar event
    'Schedule-Reply': (1 << 43),

    # A CalDAV opaque token for a calendar schedule. A response is requested
    # if the resource matches the schedule
    'If-Schedule-Tag-Match': (1 << 44),

    # COPY or MOVE request destination for a WebDAV request
    'Destination': (1 << 45),

    # A URL to a lock. Used with the UNLOCK method to remove the lock.
    'Lock-Token': (1 << 46),

    # Number of seconds for which a WebDAV LOCK should be active
    'Timeout': (1 << 47),

    # A WebDAV URI, indicates the request order of the requested collection.
    'Ordering-Type': (1 << 48),

    # A boolean indicating if a WebDAV resource should be overwritten due to
    # the request
    'Overwrite': (1 << 49),

    # A string indicating the desired position at which to insert a resource in
    # a WebDAV request
    'Position': (1 << 50),

    # Tree or graph depth of the resource on which the request should act.
    # (used by WebDAV)
    'Depth': (1 << 51),

    # Arbitrary text, when present with a POST request, indicates to the server
    # a desired description for the content to be used in URIs
    'SLUG': (1 << 52),

    # Set of header fields that will be included with the trailer of a
    # message sent using a chunked transfer encoding
    'Trailer': (1 << 53),

    # The Multipurpose Internet Mail Extensions version used when constructing
    # the components of the message. Optional.
    'MIME-Version': (1 << 54)
}

noncecache = caches['sessionarmor']


class SessionExpired(Exception):
    '''The session has expired''' 
    pass


class HmacInvalid(Exception):
    '''The HMAC did not validate''' 
    pass


def gen_header_mask(auth_headers):
    mask = 0
    for header in auth_headers:
        mask |= AUTH_HEADER_MASKS[header]
    return pack_mask(mask)


def parse_header_mask(header_mask):
    mask = bytes_to_int(header_mask)
    headers = []
    bit_n = 0
    while mask:
        if mask & 0x01:
            headers.append(ALL_AUTH_HEADERS[bit_n])
        mask >>= 1
        bit_n += 1
    return headers


def header_to_dict(header, outer_sep=';', inner_sep=':'):
    '''
    Takes a header value string of the form:
    c:<base64data0>;T_re:<base64data0>;h:<base64data1>;ignored0;
    Returns a dictionary:
    {
        'T_re': 1367448031,
        'h': <binarydata1>,
        'c': <binarydata0>,
    }
    '''
    kvs = header.split(outer_sep)
    # remove empty tokens
    kvs = (kv for kv in kvs if kv != '')
    # split key/value tokens
    kvs = (kv.split(inner_sep) for kv in kvs)
    # parse key/value tokens
    d = {kv[0]: base64.b64decode(kv[1]) for kv in kvs if len(kv) == 2}
    return d


def tuples_to_header(tuples, outer_sep=';', inner_sep=':'):
    """
    Takes a list of (k, v) string tuples and returns a string
    for the Session Armor header value
    """
    encoded_tuples = [(tup[0], base64.b64encode(tup[1])) for tup in tuples]
    LOGGER.debug(encoded_tuples)
    return outer_sep.join([inner_sep.join(tup) for tup in encoded_tuples])


def validate_ready_header(header):
    '''
    validate that there is only one header key and it is 'r'
    '''
    return len(header) == 1 and header.keys()[0] == 'r'


def validate_signed_request(header):
    # minimal set of values needed for a signed request
    valid = (header.get('s'))
             #and header.get('c')
             #and header.get('T_re')
             #and header.get('h')
             #and header.get('ah'))
    return valid


def get_client_state(header):
    '''
    Given a header dictionary, return the name of the client state.
    '''
    if validate_ready_header(header):
        return CLIENT_READY
    if validate_signed_request(header):
        return CLIENT_SIGNED_REQUEST


def pack_mask(mask):
    '''
    pack an integer as a byte string with this format
    bit length of mask cannot exceed 256

    byte0       byte1, byte2 ...
    <num_bytes> <little-endian bytestring>
    '''
    data = int_to_bytes(mask)
    data = chr(len(data)) + data
    return data


def unpack_mask(data):
    '''
    unpack a byte string as an integer with this format

    byte0       byte1, byte2 ...
    <num_bytes> <little-endian bytestring>
    '''
    mask = bytes_to_int(data[1:])
    return mask


def int_to_bytes(i):
    '''
    convert an integer to a litte-endian byte string
    '''
    if i == 0:
        return '\x00'
    res = []
    while i:
        res.append(chr(i & 0xFF))
        i >>= 8
    res.reverse()
    return ''.join(res)


def bytes_to_int(bstr):
    '''
    convert a byte string into an integer
    Input: '\x9e\x2c'
    Output: 40492
    bin(Output): '0b1001111000101100'
    '''
    vector = 0
    for i, _ in enumerate(bstr):
        vector += ord(bstr[-(i + 1)]) * (256 ** i)
    return vector


def select_hash_module(packed_hash_mask):
    '''
    Given a bit vector indicating supported hash algorithms, return a Python
    hash module for the strongest digest algorithm
    '''
    hash_mask = unpack_mask(packed_hash_mask)
    for bitmask in HASH_ALGO_MASKS:
        if bitmask[0] & hash_mask:
            return bitmask[1]
    raise NotImplementedError(
        'HMAC algorithm bitmask did not match any hash implementations.')


def select_hash_mask(header):
    '''
    Given a header dictionary, select a hash function supported by the client.

    Return a bitmask denoting the selected module.

    1. Decode base64 value of ready header
    2. Parse into bit vector
    3. Select a hash algorithm supported by the client using the bit vector
    4. Return the bitmask for the selected hash module
    '''
    # base64 decode the value of the ready key into a byte string
    hash_mask = unpack_mask(header['r'])
    # store the bit vector as an integer
    for bitmask in HASH_ALGO_MASKS:
        if bitmask[0] & hash_mask:
            return pack_mask(bitmask[0])
    raise NotImplementedError(
        'Client ready header bitmask did not match any hash implementations.')


def is_creating_session(response):
    """
    Is this response creating a new session?
    """
    sessionid = response.cookies.get(settings.SESSION_COOKIE_NAME, None)
    sessionid = getattr(sessionid, 'value', None)
    return bool(sessionid)


def extract_session_id(response):
    """
    Remove a sessionid from a response and return it as a string
    """
    sessionid = response.cookies[settings.SESSION_COOKIE_NAME]
    del response.cookies[settings.SESSION_COOKIE_NAME]
    return sessionid.value


def get_expiration_second():
    """
    Get expiration time for a new Session Armor session as seconds since epoch
    """
    #duration_seconds = 0
    duration_seconds = get_setting('S_ARMOR_SESSION_SECONDS', SECONDS_14_DAYS)
    return str(int(time.time() + duration_seconds))


def generate_hmac_key():
    """
    Generate a new key for use by the client and server to sign requests
    """
    return Random.new().read(AES.block_size)


def encrypt_opaque(sessionid, hmac_key, expiration_time):
    ctr_init = crypt_random.getrandbits(COUNTER_BITS)
    counter = Counter.new(COUNTER_BITS, initial_value=ctr_init)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=counter)
    plaintext = '|'.join((sessionid, hmac_key, expiration_time))
    LOGGER.debug("plaintext %s", plaintext)
    ciphertext = cipher.encrypt(plaintext)
    # Encrypt then MAC
    mac = hmac.new(SECRET_KEY, ciphertext, hashlib.sha256)
    ciphermac = mac.digest()
    return int_to_bytes(ctr_init), ciphermac, ciphertext


def decrypt_opaque(opaque, ctr_init, ciphermac):
    # MAC then Decrypt
    mac = hmac.new(SECRET_KEY, opaque, hashlib.sha256)
    if not hmac.compare_digest(mac.digest(), ciphermac):
        raise ValueError

    ctr_init = bytes_to_int(ctr_init)
    counter = Counter.new(COUNTER_BITS, initial_value=ctr_init)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(opaque)

    try:
        sessionid, hmac_key, expiration_time = plaintext.split('|')
    except ValueError:
        raise

    return sessionid, hmac_key, int(expiration_time)


def begin_session(header, sessionid, packed_header_mask):
    '''
    Input: client Session Armor headers when in a valid ready state
    Output: server Session Armor headers for a new session
    Side Effects: A nonce-based replay vector persisted externally
    '''
    # Create opaque token
    # Components: Session ID, HMAC Key, Expiration Time
    hmac_key = generate_hmac_key()
    # TODO: Take the expiration time from the session cookie?
    # TODO: Extend based on activity? Think about a hard and fast 5 minute
    #       expiration time. It's likely for the session to expire after a
    #       legitimate request while the user is still active.
    expiration_time = get_expiration_second()
    counter_init, ciphermac, opaque = encrypt_opaque(
        sessionid, hmac_key, expiration_time)
    LOGGER.debug("counter_init %s, ciphermac %s, opaque %s",
            counter_init, ciphermac, opaque)
    packed_hash_mask = select_hash_mask(header)

    kvs = [
        ('s', opaque),
        ('ctr', counter_init),
        ('mC', ciphermac),
        ('Kh', hmac_key),
        ('h', packed_hash_mask),
        ('ah', packed_header_mask)
    ]

    if get_setting('S_ARMOR_NONCE_REPLAY_PREVENTION', False):
        n = crypt_random.getrandbits(32)
        kvs.append(('n', int_to_bytes(n)))

    return tuples_to_header(kvs)


def get_setting(attribute, default):
    """
    Returns the value of a Django setting named by the string, attribute, or
    a default value
    """
    try:
        return settings.__getattr__(attribute)
    except AttributeError:
        return default


def auth_header_values(request, header_mask, extra_headers):
    '''
    Returns array of header values in order based on request bitmask

    If headers are not present in the request they are not included in the list
    '''
    headers = parse_header_mask(header_mask)
    values = []
    for header in headers:
        if header == 'Host':
            values.append(request.get_host())
            continue

        value = (request.META.get('HTTP_' + header.upper().replace('-', '_'),
                                  None))
        if value:
            values.append(value)

    return values


def client_hmac(algo_mask, key, string):
    digestmod = select_hash_module(algo_mask)
    mac = hmac.new(key, string, digestmod)
    return mac.digest()


def validate_request(request, request_header):
    try:
        sessionid, hmac_key, expiration_time = decrypt_opaque(
            request_header['s'], request_header['ctr'], request_header['sm'])
    except ValueError:
        raise InvalidSessionKey # Django handles this

    LOGGER.debug("request data %s %s %s",
                 sessionid, hmac_key.decode('latin1'), expiration_time)

    # Session expiration check
    if expiration_time <= int(time.time()):
        raise SessionExpired

    # HMAC validation
    # Performs time-based and nonce-based replay prevention if present

    # TODO: check if using nonce
    # using_nonce = bool based on request_header['ah']
    using_nonce = True

    # Rebuild HMAC input
    hmac_input = [request_header['n'], '+'] if using_nonce else ['+']
    hmac_input.append(request_header['t'])
    extra_headers = request_header.get('eah', [])
    hmac_input += auth_header_values(request, request_header['ah'],
                                     extra_headers)
    hmac_input.append(request.path)
    hmac_input.append(request.body or '')
    # unicode objects bytestring for ordinals greater than 128
    hmac_input = [x.decode('latin1').encode('latin1') for x in hmac_input]
    hmac_input = '|'.join(hmac_input)

    # Perform HMAC validation
    our_mac = client_hmac(request_header['h'], hmac_key, hmac_input)
    hmac_valid = hmac.compare_digest(our_mac, request_header['c'])

    if not hmac_valid:
        message = "Invalid client HMAC"
        LOGGER.debug(message)
        raise PermissionDenied(message)

    # Validate that request has not expired "time based expiry"
    # TODO test that this is comparing the right values
    if time.time() >= int(request_header['t']):
        message = "Request has expired"
        LOGGER.debug(message)
        raise PermissionDenied(message)

    # Validate that nonce has not been used before
    # TODO test that this is comparing the right values
    if using_nonce:
        nonces = noncecache.get(sessionid)
        nonces = nonces if nonces else []
        if nonces and request_header['n'] in nonces:
            message = "Request nonce has been seen before"
            LOGGER.debug(message)
            raise PermissionDenied(message)
        nonces.append(request_header['n'])
        noncecache.set(sessionid, nonces, None)

    return sessionid


def validate_session_expiry(request, request_header):
    try:
        _, _, expiration_time = decrypt_opaque(
            request_header['s'], request_header['ctr'], request_header['sm'])
    except ValueError:
        raise InvalidSessionKey # Django handles this

    # Session expiration check
    if expiration_time <= int(time.time()):
        raise SessionExpired


def invalidate_session(request_header):
    try:
        _, hmac_key, _ = decrypt_opaque(
            request_header['s'], request_header['ctr'], request_header['mC'])
    except ValueError:
        return ''
    mac = client_hmac(request_header['h'], hmac_key, 'Session Invalid')
    return tuples_to_header((('i', mac),))


class SessionArmorMiddleware(object):
    '''
    Implementation of the Session Armor protocol.

    Session Armor is an HTTP session authentication protocol hardened against
    request replay and request forgery.
    '''

    def __init__(self):
        self.strict = get_setting('S_ARMOR_STRICT', False)

        auth_headers = get_setting('S_ARMOR_AUTH_HEADERS',
                                   DEFAULT_AUTH_HEADERS)
        self.packed_header_mask = gen_header_mask(auth_headers)

    def process_request(self, request):
        '''
        Process states of the Session Armor protocol for incoming requests
        '''
        header_str = request.META.get('HTTP_X_S_ARMOR', None)   

        if not self.strict and not header_str:
            return
        elif self.strict and not header_str:
            # Disallow requests from clients that do not support SessionArmor

            # If another middleware's process_request raises an Exception
            # before this one, then the following PermissionDenied exception
            # will not be raised. This would be a breach of the authentication
            # system if this pre-empting exception is handled, and a cookie or
            # other authentication credential is used to allow a privileged
            # action. Any of the exception handlers called in the lifecycle of
            # Django's BaseHandler could allow this to happen, including the
            # handle_exception of another middleware.

            raise PermissionDenied('Client does not support Session Armor')

        request_header = header_to_dict(header_str)
        state = get_client_state(request_header)

        sessionid = None
        if state == CLIENT_SIGNED_REQUEST:
            try:
                sessionid = validate_request(request, request_header)
            except SessionExpired:
                # TODO: return HTTPResponse with "Session Expired"
                return
            except HmacInvalid:
                return

        if sessionid:
            request.COOKIES[settings.SESSION_COOKIE_NAME] = sessionid
        else:
            return

    def process_response(self, request, response):
        '''
        Process states of the Session Armor protocol for outgoing requests
        '''
        header_str = request.META.get('HTTP_X_S_ARMOR', None)

        if not header_str:
            return response

        sessionid = None
        if request.is_secure() and is_creating_session(response):
            sessionid = extract_session_id(response)

        request_header = header_to_dict(header_str)
        state = get_client_state(request_header)

        response_header = ''
        if state == CLIENT_READY and request.is_secure() and sessionid:
            LOGGER.debug("Creating new SessionArmor session from ID %s",
                         sessionid)
            response_header = begin_session(request_header, sessionid,
                                            self.packed_header_mask)
        elif state == CLIENT_SIGNED_REQUEST:
            try:
                # fastpath for expire check only
                validate_session_expiry(request, request_header)
            except SessionExpired:
                response_header = invalidate_session(request_header)

        response['X-S-Armor'] = response_header
        return response

    @staticmethod
    def do_nothing():
        '''
        Do absolutely nothing
        '''
        pass
