#!/usr/bin/env python


from django.conf import settings
settings.configure(PRINTHEADERS=True)

from django.test.client import RequestFactory

import sessionarmor.middleware


def test0():
    '''test0'''
    rf = RequestFactory()
    sam = sessionarmor.middleware.SessionArmorMiddleware()
    req = rf.get('/', X_SESSION_ARMOR='r=\x01\x61')
    sam.process_request(req)


def main():
    tests = [test0,]
    for test in tests:
        print 'TEST: {}\n'.format(test.__doc__)
        test()
        print 


if __name__ == '__main__':
    main()
