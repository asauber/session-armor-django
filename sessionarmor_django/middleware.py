'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2013 - 2016 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt

TODO: Audit for comparison-based timing attacks
'''


import base64
import hashlib
import hmac
import logging
import time
from datetime import datetime, timedelta

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import random as crypt_random
from Crypto.Util import Counter
from django.conf import settings
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


class SessionExpired(Exception):
    '''The session has expired''' 
    pass


class HmacInvalid(Exception):
    '''The HMAC did not validate''' 
    pass


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


def build_bit_vector_from_bytes(bstr):
    '''
    convert a byte string into an integer
    Input: '\x9e\x2c'
    Output: 40492
    bin(Output): '0b1001111000101100'
    '''
    vector = 0
    for i, _ in enumerate(bstr):
        vector += ord(bstr[-i]) * (256 ** i)
    return vector


def select_digest_module(algos_vector):
    '''
    Given a bit vector indicating supported hash algorithms, return a Python
    hash module for the strongest digest algorithm
    '''
    algos_vector = build_bit_vector_from_bytes(algos_vector)
    for bitmask in HASH_ALGO_MASKS:
        if bitmask[0] & algos_vector:
            return bitmask[1]
    raise NotImplementedError(
        'HMAC algorithm bitmask did not match any hash implementations.')


def select_hash_algo(header):
    '''
    Given a header dictionary, select a hash function supported by the
    client.

    Return a bitmask denoting the selected module.

    1. Decode base64 value of ready header
    2. Parse into bit vector
    3. Select a hash algorithm supported by the client using the bit vector
    4. Return the bitmask for the selected hash module
    '''
    # base64 decode the value of the ready key into a byte string
    ready_str = header['r']
    # store the bit vector as an integer
    algos_vector = build_bit_vector_from_bytes(ready_str[1:])
    for bitmask in HASH_ALGO_MASKS:
        if bitmask[0] & algos_vector:
            return bitmask[0]
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
    return ctr_init, ciphermac, ciphertext


def decrypt_opaque(opaque, ctr_init, ciphermac):
    # MAC then Decrypt
    mac = hmac.new(SECRET_KEY, opaque, hashlib.sha256)
    if not hmac.compare_digest(mac.digest(), ciphermac):
        raise ValueError

    counter = Counter.new(COUNTER_BITS, initial_value=ctr_init)
    cipher = AES.new(SECRET_KEY, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(opaque)

    try:
        sessionid, hmac_key, expiration_time = plaintext.split('|')
    except ValueError:
        raise

    return sessionid, hmac_key, int(expiration_time)


def begin_session(header, sessionid):
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
    hashalgo = select_hash_algo(header)

    kvs = (
        ('s', opaque),
        # TODO: Can we encode the integers in binary format as well?
        ('ctr', str(counter_init)),
        ('mC', ciphermac),
        ('Kh', hmac_key),
        # Would we want to?
        ('h', str(hashalgo))
    )
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


def validate_request(request_header):
    try:
        sessionid, hmac_key, expiration_time = decrypt_opaque(
                request_header['s'], request_header['ctr'], request_header['mC'])
    except ValueError:
        raise InvalidSessionKey # Django handles this

    LOGGER.debug("request data %s %s %s", sessionid, hmac_key, expiration_time)

    if expiration_time <= int(time.time()):
        raise SessionExpired

    # HMAC verification
    # ...
    #    raise HmacInvalid

    return sessionid


def invalidate_session(request_header):
    try:
        _, hmac_key, _ = decrypt_opaque(
                request_header['s'], request_header['ctr'], request_header['mC'])
    except ValueError:
        return ''
    digestmod = select_digest_module(request_header['h'])
    mac = hmac.new(hmac_key, "Session Expired", digestmod)
    return tuples_to_header((('i', mac.digest()),))


class SessionArmorMiddleware(object):
    '''
    Implementation of the Session Armor protocol.

    Session Armor is an HTTP session authentication protocol hardened against
    request replay and request forgery.
    '''

    def __init__(self):
        self.strict = get_setting('STRICT_S_ARMOR', False)

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
                sessionid = validate_request(request_header)
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
            response_header = begin_session(request_header, sessionid)
        elif state == CLIENT_SIGNED_REQUEST:
            try:
                validate_request(request_header)
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
