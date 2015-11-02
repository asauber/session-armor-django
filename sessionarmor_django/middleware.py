'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2013 - 2015 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt
'''


import base64
from django.conf import settings


CLIENT_READY = 'ready'


def header_to_dict(header, outer_sep=';', inner_sep=':'):
    '''
    Takes a header value of the form:
    c:<base64data0>;T_re:1367448031;h:<base64data1>;ignored0;
    Returns a dictionary:
    {
        'c': <base64data0>,
        'T_re': 1367448031,
        'h': <base64data1>,
    }
    '''
    kvs = header.split(outer_sep)
    # remove empty tokens
    kvs = (kv for kv in kvs if kv != '')
    # split key/value tokens
    kvs = (kv.split(inner_sep) for kv in kvs)
    # parse key/value tokens
    d = {kv[0]: kv[1] for kv in kvs if len(kv) == 2}
    return d


def get_client_state(header):
    '''
    Given a header dictionary, return the name of the client state
    '''
    if len(header) == 1 and header.keys()[0] == 'r':
        return CLIENT_READY


def select_hash_module(header):
    '''
    Given a header dictionary, select a hash function supported by the
    client.

    Return the Python module implementing this hash function expected by
    the hmac module.
    '''
    # base64 decode the value of the ready key
    bitmask_str = base64.b64decode(header['r'])
    print 'hash algo bitmask as hex', bitmask_str.encode('hex')


def process_ready_header(header):
    '''
    Decode base64 value of ready header
    Parse into bit vector
    Select a hash algorithm supported by the client using the bit vector
    '''
    hashmod = select_hash_module(header) 


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
        header = header_to_dict(request.META['HTTP_X_S_ARMOR'])
        state = get_client_state(header)
        if state == CLIENT_READY:
            process_ready_header(header)

    def process_response(self, request, response):
        '''
        Process stages of the Session Armor protocol for outgoing requests
        '''
        return response
