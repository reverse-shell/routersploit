from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):

    """Scanner implementation for HooToo vulnerabilities."""

    __info__ = {
        'name': 'HooToo Scanner',
        'description': 'Scanner module for HooToo routers',
        'authors': [
            'Tao "depierre" Sauvage',
        ],
        'references': (
            'http://blog.ioactive.com/2018/04/hootoo-tripmate-routers-are-cute-but.html',
            'https://www.ioactive.com/pdfs/HooToo_Security_Advisory_FINAL_4.19.18.pdf'
        ),
        'devices': (
            'HooToo TripMate',
        ),
    }
    modules = ['routers/hootoo', 'cameras/hootoo', 'misc/hootoo']
