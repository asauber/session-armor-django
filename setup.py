from distutils.core import setup

setup(
    name='session-armor-django',
    packages=['sessionarmor_django'],
    license='MIT',
    version='0.1.0',
    description='Session Armor authentication procotol, Django middleware',
    author='Andrew Sauber',
    author_email='a3sauber@gmail.com',
    url='https://www.bitbucket.org/asauber/session-armor-django',
    keywords=['django','authentication','middleware','HTTP'],
    install_requires=['cryptography',],
)
