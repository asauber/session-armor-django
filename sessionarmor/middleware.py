'''
Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2013 - 2015 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt
'''


from django.conf import settings


class SessionArmorMiddleware(object):
    '''
    Implementation of the Session Armor protocol.

    Session Armor is an HTTP session authentication protocol hardened against
    request replay and request forgery.
    '''
    def process_request(self, request):
        '''
        Process stages of the Session Armor protocol for incoming requests

        For now, print all headers from each request to stdout
        '''
        if not settings.PRINTHEADERS:
            return

        for name, value in request.META.iteritems():
            print name, ':', value

    def process_response(self, request, response):
        '''
        Process stages of the Session Armor protocol for outgoing requests
        '''
        return response
