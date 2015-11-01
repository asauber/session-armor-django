'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2013 - 2015 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt
'''


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

    def process_response(self, request):
        '''
        Process stages of the Session Armor protocol for outgoing requests
        '''
        pass
