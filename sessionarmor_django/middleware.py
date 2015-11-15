'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2013 - 2015 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt
'''


# pylint: disable=no-self-use


import base64
import hashlib


CLIENT_READY = 'ready'

# the following are stored in order of preference
HASH_ALGO_MASKS = (
    (1 << 2, hashlib.sha512),
    (1 << 1, hashlib.sha384),
    (1 << 0, hashlib.sha256),
    (1 << 3, lambda: hashlib.new('ripemd160')),
)


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
        'Client ready header bitmask did not match any hash implementations.')


def select_hash_module(header):
    '''
    Given a header dictionary, select a hash function supported by the
    client.

    Return the Python module implementing this hash function as expected by
    the hmac module.

    1. Decode base64 value of ready header
    2. Parse into bit vector
    3. Select a hash algorithm supported by the client using the bit vector
    '''
    # base64 decode the value of the ready key into a byte string
    ready_str = base64.b64decode(header['r'])
    # store the bit vector as an integer
    algos_vector = build_bit_vector_from_bytes(ready_str[1:])
    digest_mod = select_digest_module(algos_vector)
    return digest_mod


def process_client_ready(header):
    '''
    Input: client Session Armor headers when in a valid ready state
    Output: server Session Armor headers for a new session
    Side Effects: A nonce-based replay vector persisted externally
    '''
    hashmodule = select_hash_module(header)


class SessionArmorMiddleware(object):
    '''
    Implementation of the Session Armor protocol.

    Session Armor is an HTTP session authentication protocol hardened against
    request replay and request forgery.
    '''
    def process_request(self, request):
        '''
        Process stages of the Session Armor protocol for incoming requests
        '''
        pass

    def process_response(self, request, response):
        '''
        Process stages of the Session Armor protocol for outgoing requests
        '''
        header = header_to_dict(request.META['HTTP_X_S_ARMOR'])
        state = get_client_state(header)
        if state == CLIENT_READY:
            process_client_ready(header)

        return response

    @staticmethod
    def do_nothing():
        '''
        Do absolutely nothing
        '''
        pass
