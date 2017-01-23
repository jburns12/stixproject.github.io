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
    data = {
        'indicators': {
        }
    }

    ttps = {}
    for ttp in stix_package.ttps:
        ttps[ttp.id_] = ttp
        data['indicators'][ttp.title] = []

    for indicator in stix_package.indicators:
        ip = indicator.observable.object_.properties.address_value.value
        ttp = ttps[indicator.indicated_ttps[0].item.idref]
        data['indicators'][ttp.title].append(ip)

    print(data)

if __name__ == '__main__':
    try:
        fname = sys.argv[1]
    except:
        exit(1)

    fd = open(fname)
    stix_pkg = STIXPackage.from_xml(fd)

    parse_stix(stix_pkg)
