from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Ubiquiti vulnerabilities.
    """
    __info__ = {
        'name': 'Ubiquiti Scanner',
        'description': 'Scanner module for Ubiquiti devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Ubiquiti',
        ),
    }
    vendor = ['routers/ubiquiti', 'cameras/ubiquiti', 'misc/ubiquiti']
