'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2013 - 2015 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt
'''


import base64
from Crypto import Random
from Crypto.Random import random as crypt_random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from datetime import datetime, timedelta
from django.conf import settings
from django.core.exceptions import PermissionDenied
import hashlib
import logging


COUNTER_BITS = 128
CLIENT_READY = 'ready'
EPOCH_DATETIME = datetime.utcfromtimestamp(0)
HASH_ALGO_MASKS = (
    # these hashing algorithms are in order of preference
    (1 << 2, hashlib.sha512),
    (1 << 1, hashlib.sha384),
    (1 << 0, hashlib.sha256),
    (1 << 3, lambda: hashlib.new('ripemd160')),
)
LOGGER = logging.getLogger(__name__)
MINUTES_14_DAYS = 20160
assert len(settings.SECRET_KEY) >= AES.block_size, \
    "Django settings.SECRET_KEY must be at least {} bytes".format(
        AES.block_size)
SECRET_KEY = bytes(settings.SECRET_KEY[:AES.block_size])


def header_to_dict(header, outer_sep=';', inner_sep=':'):
    '''
    Takes a header value string of the form:
    c:<base64data0>;T_re:1367448031;h:<base64data1>;ignored0;
    Returns a dictionary:
    {
        'T_re': 1367448031,
        'h': <base64data1>,
        'c': <base64data0>,
    }
    '''
    kvs = header.split(outer_sep)
    # remove empty tokens
    kvs = (kv for kv in kvs if kv != '')
    # split key/value tokens
    kvs = (kv.split(inner_sep) for kv in kvs)
    # parse key/value tokens
    digest = {kv[0]: kv[1] for kv in kvs if len(kv) == 2}
    return digest


def tuples_to_header(tuples, outer_sep=';', inner_sep=':'):
    """
    Takes a list of (k, v) string tuples and returns a string
    for the Session Armor header value
    """
    return outer_sep.join([inner_sep.join(tup) for tup in tuples])


def validate_ready_header(header):
    '''
    validate that there is only one header key and it is 'r'
    '''
    return len(header) == 1 and header.keys()[0] == 'r'


def get_client_state(header):
    '''
    Given a header dictionary, return the name of the client state.
    '''
    if validate_ready_header(header):
        return CLIENT_READY


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
    ready_str = base64.b64decode(header['r'])
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
    sessionid = response.cookies.get('sessionid', None)
    sessionid = getattr(sessionid, 'value', None)
    return bool(sessionid)


def extract_session_id(response):
    """
    Remove a sessionid from a response and return it as a string
    """
    sessionid = response.cookies['sessionid']
    del response.cookies['sessionid']
    return sessionid


def get_expiration_second():
    """
    Get expiration time for a new Session Armor session as seconds since epoch
    """
    duration_minutes = get_setting('S_ARMOR_SESSION_MINUTES',
                                   MINUTES_14_DAYS)
    minutes_delta = timedelta(minutes=duration_minutes)
    expiration_time = datetime.now() + minutes_delta
    return str((expiration_time - EPOCH_DATETIME).total_seconds())


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
    hashmod = hashlib.sha256()
    hashmod.update(ciphertext)
    cipherhash = hashmod.digest()
    return ctr_init, cipherhash, ciphertext


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
    counter_init, cipherhash, opaque = encrypt_opaque(
        sessionid, hmac_key, expiration_time)
    LOGGER.debug("counter_init %s, cipherhash %s, opaque %s",
            counter_init, cipherhash, opaque)
    hashalgo = select_hash_algo(header)

    kvs = (
        ('s', base64.b64encode(opaque)),
        ('ctr', base64.b64encode(str(counter_init))),
        ('hC', base64.b64encode(cipherhash)),
        ('Kh', base64.b64encode(hmac_key)),
        ('h', base64.b64encode(str(hashalgo)))
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
            return None
        elif self.strict and not header_str:
            # If another middleware's process_request raises an Exception
            # before this one, then the following PermissionDenied exception
            # will not be raised. This could be considered a breach of
            # authentication if any of the exception handlers called in the
            # lifecycle of Django's BaseHandler allow an authenticated action
            # to proceed.
            raise PermissionDenied('Client does not support Session Armor')

    def process_response(self, request, response):
        '''
        Process states of the Session Armor protocol for outgoing requests
        '''
        header_str = request.META.get('HTTP_X_S_ARMOR', None)

        if not header_str:
            return response

        request_header = header_to_dict(header_str)
        state = get_client_state(request_header)

        response_header = ''
        if (state == CLIENT_READY and request.is_secure()
                and is_creating_session(response)):
            # Begin a new protected session
            sessionid = extract_session_id(response).value
            LOGGER.debug("Creating new SessionArmor session from ID %s",
                         sessionid)
            response_header = begin_session(request_header, sessionid)

        response['X-S-Armor'] = response_header
        return response

    @staticmethod
    def do_nothing():
        '''
        Do absolutely nothing
        '''
        pass
