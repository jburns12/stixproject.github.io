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
        print("== INDICATOR ==")
        print("Title: " + indicator.title)
        print("Description: " + indicator.description.value)

        for tm in indicator.test_mechanisms:
            print("Producer: " + tm.producer.identity.name)
            print("Rule: %s" % tm.rule)

if __name__ == '__main__':
    try:
        fname = sys.argv[1]
    except:
        exit(1)

    fd = open(fname)
    stix_pkg = STIXPackage.from_xml(fd)

    parse_stix(stix_pkg)
