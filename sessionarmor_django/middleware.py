'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2015 - 2016 Andrew Sauber

This software is licensed under AGPLv3 open source license. See LICENSE.txt

Example configuration variables:
S_ARMOR_STRICT = True
# 14 days
S_ARMOR_SESSION_VALID_SECONDS = 1209600
# 5 minutes
S_ARMOR_REQUEST_VALID_SECONDS = 300
# 30 minutes
S_ARMOR_INACTIVITY_TIMEOUT_SECONDS = 1800
S_ARMOR_AUTH_HEADERS = [
    'Host',
    'User-Agent',
    'Accept',
    'Accept-Encoding',
    'Accept-Language',
    'Referer',
    'Cookie',
    'Accept-Charset',
    'Range',
    'Date',
    'Authorization',
    'Origin',
    'DNT',
    'X-Csrf-Token',
]
# Must have a persistent Django cache named "sessionarmor" configured for this
# feature to work
# "persistent" means:
#   * TIMEOUT is set to None
#   * MAX_ENTRIES is set larger than your max active sessions (maybe millions)
#   * CULL_FREQUENCY is set to float('inf') or culling is disabled
#   * The cache supports no-expiry, by passing None as the timeout
S_ARMOR_NONCE_REPLAY_PREVENTION = True
S_ARMOR_EXTRA_AUTHENTICATED_HEADERS = [
    'X-Client-App-Version',
    'X-Legacy-App',
]
'''


import base64
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import random as crypt_random
from Crypto.Util import Counter
from django.conf import settings
from django.contrib.sessions.exceptions import InvalidSessionKey
from django.core.cache import caches
from django.core.exceptions import PermissionDenied

COUNTER_BITS = 128
RECIEPT_VECTOR_BITS = 64
# All 1s followed by one 0
# Meaning: The first nonce hasn't been seen yet, but don't allow any
# lower-numbered invalid nonces.
INITIAL_RECIEPT_VECTOR = ((2 ** RECIEPT_VECTOR_BITS) - 2)
RECIEPT_VECTOR_MASK = (2 ** RECIEPT_VECTOR_BITS) - 1

CLIENT_READY = 'ready'
CLIENT_SIGNED_REQUEST = 'request'

HASH_ALGO_MASKS = (
    # these hashing algorithms are in order of preference
    (1 << 2, hashlib.sha512),
    (1 << 1, hashlib.sha384),
    (1 << 0, hashlib.sha256),
    (1 << 3, lambda: hashlib.new('ripemd160')),
)

SECONDS_14_DAYS = 1209600
SECONDS_5_MINUTES = 300
SECONDS_30_MINUTES = 1800

LOGGER = logging.getLogger(__name__)

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
    # Hostname to which the client is sending the request
    'Host',

    # String indicating the software and/or hardware platform used to generate
    # the request
    'User-Agent',

    # Types of media that the client would accept in a response
    'Accept',

    # Desired behavior of the connection with the first remote machine
    'Connection',

    # Character encodings that the client would accept in a response
    'Accept-Encoding',

    # Human languages that the client would accept in a response
    'Accept-Language',

    # URI that caused or enabled the client to make the request
    'Referer',

    # Persistent general-purpose tokens that the client provides to the server
    'Cookie',

    # Character sets that the client would accept in a response
    'Accept-Charset',

    # The last modified time known by the client, response requested if
    # modified
    'If-Modified-Since',

    # An entity tag. A response is requested if the entity does not match.
    'If-None-Match',

    # Specifies a portion of the resource being requested
    'Range',

    # Time at which a request was sent that includes body data
    'Date',

    # Authentication credentials provided by the client for Basic or Digest
    # HTTP Authentication
    'Authorization',

    # An indication of how the request should be treated by caching proxies
    'Cache-Control',

    # A list of origins that caused the request, e.g. used by a client script
    # that has established allowable cross-origin methods via CORS
    'Origin',

    # General-purpose header field, most often used with "no-cache" to request
    # a non-cached version of a resource
    'Pragma',

    # Boolean indicating that the user wishes not to be tracked by the server
    'DNT',

    # Nonce sent by the server to be used for Cross Site Request Forgery
    # protection
    'X-Csrf-Token',

    # Version of the WebSocket protocol being used
    'Sec-WebSocket-Version',

    # Used with websocket handshake to indicate what application level
    # protocols the client wishes to use
    'Sec-WebSocket-Protocol',

    # Randomly generated nonce used during the Websocket handshake
    'Sec-WebSocket-Key',

    # A list of registered websocket extended features that the client wishes
    # to use with a websocket connection
    'Sec-WebSocket-Extensions',

    # Transfer Encodings that the user agent will accept, e.g. "deflate". Can
    # also specify that "trailers" should be used for chunked transfers
    'TE',

    # Mechanism used to make the request, e.g. XMLHttpRequest
    'X-Requested-With',

    # IP addres or hostname that originated the request (after travelling
    # through a proxy)
    'X-Forwarded-For',

    # The original protocol used when the request was made, e.g. "https" (after
    # travelling through a proxy
    'X-Forwarded-Proto',

    # Used by a proxy server to include information that would otherwise be
    # lost at lower levels in the protocol stack
    'Forwarded',

    # The email address of the user making the request, most often used by
    # robots as contact information for the robot administrator
    'From',

    # Settings for protocol-upgrade with an HTTP/2 capable host
    'HTTP2-Settings',

    # Another protocol, to which the agent wishes to switch, e.g. HTTP/2.0
    'Upgrade',

    # Credentials request by a proxy in the request chain. Consumed by the
    # first proxy requesting authentication.
    'Proxy-Authorization',

    # List of conditions for a resource to meet for a response to be requested
    'If',

    # An entity tag that must match the resource for a response to be requested
    'If-Match',

    # Combination of If-Match and If-Unmodified-Since for a range request
    'If-Range',

    # A timestamp. A response is requested if the entity has not been modified
    # since this time.
    'If-Unmodified-Since',

    # An integer. Used with TRACE or OPTIONS requests to limit forwarding by
    # proxies
    'Max-Forwards',

    # Preferences requested of the server, examples include: asynchronous
    # response, relative priority, response verbosity
    'Prefer',

    # A list of proxies through which the request was sent
    'Via',

    # Protocol stack that that the client would like to tunnel via HTTP
    'ALPN',

    # Expected response from the server, usually HTTP 100 (Continue). In this
    # case the client wishes to know if a request body is acceptable before
    # sending it to the server.
    'Expect',

    # Alternative host that the client selected for a request
    'Alt-Used',

    # Client indicating whether or not it would like timezones on calendars
    'CalDAV-Timezones',

    # A boolean, indicates if a client will attend a CalDAV calendar event
    'Schedule-Reply',

    # A CalDAV opaque token for a calendar schedule. A response is requested
    # if the resource matches the schedule
    'If-Schedule-Tag-Match',

    # COPY or MOVE request destination for a WebDAV request
    'Destination',

    # A URL to a lock. Used with the UNLOCK method to remove the lock.
    'Lock-Token',

    # Number of seconds for which a WebDAV LOCK should be active
    'Timeout',

    # A WebDAV URI, indicates the request order of the requested collection.
    'Ordering-Type',

    # A boolean indicating if a WebDAV resource should be overwritten due to
    # the request
    'Overwrite',

    # A string indicating the desired position at which to insert a resource in
    # a WebDAV request
    'Position',

    # Tree or graph depth of the resource on which the request should act.
    # (used by WebDAV)
    'Depth',

    # Arbitrary text, when present with a POST request, indicates to the server
    # a desired description for the content to be used in URIs
    'SLUG',

    # Set of header fields that will be included with the trailer of a
    # message sent using a chunked transfer encoding
    'Trailer',

    # The Multipurpose Internet Mail Extensions version used when constructing
    # the components of the message. Optional.
    'MIME-Version'
]

AUTH_HEADER_MASKS = {name: (1 << i) for (i, name)
                     in enumerate(ALL_AUTH_HEADERS)}

NONCECACHE = caches['sessionarmor']


class HmacInvalid(Exception):
    def __init__(self, message="The client's HMAC did not validate"):
        self.message = message

    def __str__(self):
        return self.message


class OpaqueInvalid(Exception):
    def __init__(self, message=
            "The opaque token from the client was not valid"):
        self.message = message

    def __str__(self):
        return self.message


class RequestExpired(Exception):
    def __init__(self, message="The request has expired"):
        self.message = message

    def __str__(self):
        return self.message


class NonceInvalid(Exception):
    def __init__(self, message="The replay-prevention nonce was invalid"):
        self.message = message

    def __str__(self):
        return self.message


class SessionExpired(Exception):
    def __init__(self, message="The session has expired"):
        self.message = message

    def __str__(self):
        return self.message


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
    return outer_sep.join([inner_sep.join(tup) for tup in encoded_tuples])


def validate_ready_header(header):
    '''
    validate that there is only one header key and it is 'r'
    '''
    return len(header) == 1 and header.keys()[0] == 'r'


def validate_signed_request(header):
    # minimal set of values needed for a signed request
    valid = (header.get('s')
             and header.get('c')
             and header.get('t')
             and header.get('h')
             and header.get('ah'))
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
    raise HmacInvalid(
        'HMAC algorithm bitmask did not match any hash implementations.')


def select_hash_mask(packed_hash_mask):
    '''
    Given a header dictionary, select a hash function supported by the client.

    Return a bitmask denoting the selected module.

    1. Decode base64 value of ready header
    2. Parse into bit vector
    3. Select a hash algorithm supported by the client using the bit vector
    4. Return the bitmask for the selected hash module
    '''
    # base64 decode the value of the ready key into a byte string
    hash_mask = unpack_mask(packed_hash_mask)
    # store the bit vector as an integer
    for bitmask in HASH_ALGO_MASKS:
        if bitmask[0] & hash_mask:
            return pack_mask(bitmask[0])
    raise HmacInvalid(
        'Client ready header bitmask did not match any hash algorithms.')


def is_modifying_session(response):
    """
    Is this response creating a new session?
    """
    sessionid = response.cookies.get(settings.SESSION_COOKIE_NAME, None)
    sessionid = getattr(sessionid, 'value', None)
    return bool(sessionid is not None)


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
    session_duration_seconds = get_setting(
        'S_ARMOR_SESSION_VALID_SECONDS', SECONDS_14_DAYS)
    return str(int(time.time() + session_duration_seconds))


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
    ciphertext = cipher.encrypt(plaintext)
    # Encrypt then MAC (EtM) provices integrity for the ciphertext and prevents
    # oracle attacks
    mac = hmac.new(SECRET_KEY, ciphertext, hashlib.sha256)
    ciphermac = mac.digest()
    return int_to_bytes(ctr_init), ciphermac, ciphertext


def decrypt_opaque(opaque, ctr_init, ciphermac):
    # MAC then Decrypt (MtD)
    mac = hmac.new(SECRET_KEY, opaque, hashlib.sha256)
    if not hmac.compare_digest(mac.digest(), ciphermac):
        raise OpaqueInvalid(
            "Opaque token from the client failed to authenticate")

    ctr_init = bytes_to_int(ctr_init)
    counter = Counter.new(COUNTER_BITS, initial_value=ctr_init)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(opaque)

    try:
        sessionid, remainder = plaintext.split('|', 1)
        hmac_key, expiration_time = (remainder[:AES.block_size],
                                     remainder[AES.block_size + 1:])
    except ValueError:
        raise OpaqueInvalid(
            "Plaintext from opaque token didn't have required fields")

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
    expiration_time = get_expiration_second()
    counter_init, ciphermac, opaque = encrypt_opaque(
        sessionid, hmac_key, expiration_time)
    packed_hash_mask = select_hash_mask(header['r'])

    kvs = [
        ('s', opaque),
        ('ctr', counter_init),
        ('cm', ciphermac),
        ('kh', hmac_key),
        ('h', packed_hash_mask),
        ('ah', packed_header_mask)
    ]

    if get_setting('S_ARMOR_NONCE_REPLAY_PREVENTION', False):
        n = crypt_random.getrandbits(32)
        kvs.append(('n', int_to_bytes(n)))

    eah = get_setting('S_ARMOR_EXTRA_AUTHENTICATED_HEADERS', [])
    if eah:
        kvs.append(('eah', ",".join(eah)))

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
    headers = headers + extra_headers
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


def server_hmac(algo_mask, key, string):
    digestmod = select_hash_module(algo_mask)
    mac = hmac.new(key, string, digestmod)
    return mac.digest()


def validate_nonce(request_nonce, sessionid):
    request_nonce = bytes_to_int(request_nonce)
    nonce_tup = NONCECACHE.get(sessionid)
    if nonce_tup:
        latest_nonce, reciept_vector = nonce_tup
    else:
        latest_nonce, reciept_vector = (request_nonce,
                                        INITIAL_RECIEPT_VECTOR)

    delta = latest_nonce - request_nonce

    if delta < 0:
        # This a "future" nonce
        latest_nonce = request_nonce
        # Shift our current vector to the left
        reciept_vector <<= -delta
        # And set that this new nonce has been seen
        reciept_vector |= 0x01
    elif delta >= 0 and delta < RECIEPT_VECTOR_BITS:
        # This is a "past" nonce that we have the ability to check
        if reciept_vector & (1 << delta):
            message = "Request nonce has been seen before"
            raise NonceInvalid(message)
        else:
            # Set the bit in the bit vector
            reciept_vector |= 1 << delta
    elif delta > 0 and delta >= RECIEPT_VECTOR_BITS:
        # This is "past" nonce that we don't have the ability to check
        message = "Nonce is too old to validate"
        raise NonceInvalid(message)

    # Clamp to RECIEPT_VECTOR_BITS because otherwise Python will gladly shift
    # our vector into a bigint
    reciept_vector &= RECIEPT_VECTOR_MASK
    NONCECACHE.set(sessionid, (latest_nonce, reciept_vector), None)


def validate_request(request, request_header):
    sessionid, hmac_key, expiration_time = decrypt_opaque(
        request_header['s'], request_header['ctr'], request_header['cm'])

    # Session expiration check
    if expiration_time <= int(time.time()):
        raise SessionExpired('Session expired due to absolute expiration time')

    # HMAC validation
    # Performs time-based and nonce-based replay prevention if present

    # Rebuild HMAC input
    using_nonce = bool(request_header.get('n', None))
    hmac_input = [request_header['n'], '+'] if using_nonce else ['+']
    hmac_input.append(request_header['t'])
    hmac_input.append(request_header['lt'])
    extra_headers = request_header.get('eah', None)
    extra_headers = extra_headers.split(',') if extra_headers else []
    hmac_input += auth_header_values(request, request_header['ah'],
                                     extra_headers)
    hmac_input.append(request.get_full_path())
    hmac_input.append(request.body or '')
    # unicode objects to bytestring for ordinals greater than 128
    hmac_input = [x.decode('latin1').encode('latin1') for x in hmac_input]
    hmac_input = '|'.join(hmac_input)

    # Perform HMAC validation
    our_mac = server_hmac(request_header['h'], hmac_key, hmac_input)
    hmac_valid = hmac.compare_digest(our_mac, request_header['c'])

    if not hmac_valid:
        raise HmacInvalid()

    # If the request is valid, but too much time has elapsed since the prior
    # request, expire the session. Note that it's fine to do this before replay
    # prevetion, because even if an attacker were trying to maliciously replay
    # the request, it embeds information that will always expire the session,
    # namely, the request time and the prior request time. Both of these are
    # included in the HMAC.
    inactivity_timeout_seconds = get_setting(
        'S_ARMOR_INACTIVITY_TIMEOUT_SECONDS', SECONDS_30_MINUTES)
    if (int(request_header['t']) - int(request_header['lt']) >=
            inactivity_timeout_seconds):
        raise SessionExpired('Session expired due to inactivity')

    # Validate that the request has not expired (time-based replay prevention)
    # NB: This is done after HMAC validation
    request_duration_seconds = get_setting(
        'S_ARMOR_REQUEST_VALID_SECONDS', SECONDS_5_MINUTES)
    if time.time() - int(request_header['t']) >= request_duration_seconds:
        raise RequestExpired()

    # Validate that nonce has not been used before (absolute replay prevention)
    if using_nonce:
        validate_nonce(request_header['n'], sessionid)

    return sessionid


def validate_session_expiry(request, request_header):
    # Absolute expiration check
    _, _, expiration_time = decrypt_opaque(
        request_header['s'], request_header['ctr'], request_header['cm'])
    if expiration_time <= int(time.time()):
        raise SessionExpired('Session expired due to absolute expiration time')

    # Inactivity expiration check
    inactivity_timeout_seconds = get_setting(
        'S_ARMOR_INACTIVITY_TIMEOUT_SECONDS', SECONDS_30_MINUTES)
    if (int(request_header['t']) - int(request_header['lt']) >=
            inactivity_timeout_seconds):
        raise SessionExpired('Session expired due to inactivity')


def invalidate_session(request_header):
    _, hmac_key, _ = decrypt_opaque(
        request_header['s'], request_header['ctr'], request_header['cm'])
    mac = server_hmac(request_header['h'], hmac_key, 'Session Expired')
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
            #
            # NB: This applies to all PermissionDenied exceptions called from
            # the context of this middleware.
            raise PermissionDenied('Client does not support Session Armor')

        request_header = header_to_dict(header_str)
        state = get_client_state(request_header)

        sessionid = None

        if state == CLIENT_READY and request.is_secure():
            try:
                selected_hash_mask = select_hash_mask(request_header['r'])
            except HmacInvalid as e:
                # Client provided an invalid HMAC algo mask
                LOGGER.debug(str(e))
                raise PermissionDenied(str(e))
        elif state == CLIENT_SIGNED_REQUEST:
            try:
                sessionid = validate_request(request, request_header)
            except SessionExpired as e:
                LOGGER.debug(str(e))
                # Return before injeting the session cookie. The request will
                # be processed without a user object. This allows session
                # invalidation to proceed in process_response.
                return
            except OpaqueInvalid as e:
                # Client provided an invalid symmetrically encrypted token
                LOGGER.debug(str(e))
                raise PermissionDenied(str(e))
            except HmacInvalid as e:
                # Client's HMAC did not validate
                LOGGER.debug(str(e))
                raise PermissionDenied(str(e))
            except RequestExpired as e:
                # Time-based replay prevention
                LOGGER.debug(str(e))
                raise PermissionDenied(str(e))
            except NonceInvalid as e:
                # Counter-based replay prevention
                LOGGER.debug(str(e))
                raise PermissionDenied(str(e))

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
        if request.is_secure() and is_modifying_session(response):
            sessionid = extract_session_id(response)

        request_header = header_to_dict(header_str)
        state = get_client_state(request_header)

        if state == CLIENT_READY and request.is_secure() and sessionid:
            try:
                response['X-S-Armor'] = begin_session(
                    request_header, sessionid, self.packed_header_mask)
            except HmacInvalid as e:
                # If the algo mask was invalid then PermissionDenied was raised
                # in ProcessRequest
                return response
        elif state == CLIENT_SIGNED_REQUEST:
            # Session invalidation
            try:
                # Check if the session has expired
                try:
                    validate_session_expiry(request, request_header)
                except SessionExpired:
                    response['X-S-Armor'] = invalidate_session(request_header)
                # Check if the server is deleting the session, e.g. a logout
                # view has executed.
                if sessionid == '':
                    response['X-S-Armor'] = invalidate_session(request_header)
            except OpaqueInvalid:
                # Can't raise PermissionDenied; it won't be caught by Django.
                # We have already risen it above if the opaque is invalid.
                return response

        return response
