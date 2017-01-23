#!/usr/bin/env python
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

'''
The following code requires python-stix v1.1.1.0 or greater installed.
For installation instructions, please refer to https://github.com/STIXProject/python-stix.
'''

import sys
from stix.core import STIXPackage


def parse_stix(stix_package):
    for indicator in stix_package.indicators:
        print("Hash: " + indicator.observable.object_.properties.hashes[0].simple_hash_value.value)
        print("Reputation: " + indicator.confidence.value.value)
        print("TTP: " + indicator.indicated_ttps[0].item.title)


if __name__ == '__main__':
    try:
        fname = sys.argv[1]
    except:
        exit(1)

    fd = open(fname)
    stix_pkg = STIXPackage.from_xml(fd)

    parse_stix(stix_pkg)
