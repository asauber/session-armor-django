# Session Armor Protocol, Django Middleware Implementation

Copyright (C) 2015 - 2016 Andrew Sauber

This software is licensed under the MIT open source license. See LICENSE.txt

## Installation

`python setup.py install`

## Usage

Add `'sessionarmor_django.middleware.SessionArmorMiddleware'` to your
`MIDDLEWARE_CLASSES` setting.

Add `STRICT_S_ARMOR = True` to your settings.py if you would like to enforce
that all requests support Session Armor. It's not necessary to include this
setting if you would like Session Armor to be optional.  Django's
PermissionDenied exception will be raised for those clients who do not support
Session Armor. This generates a 403 response for the client. If you would like
to customize the 403 response to indicate that Session Armor is required, see
https://docs.djangoproject.com/en/1.9/ref/views/#the-403-http-forbidden-view.

## Development

`pip install -e .`

## License

Licensed under the Affero GPLv3. This is to discourage you from using it in production until it's production-ready. ;)

A more permissive license may be used in the future.
