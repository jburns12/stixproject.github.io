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
        'incidents': {
        }
    }

    ttps = {}
    for ttp in stix_package.ttps:
        ttps[ttp.id_] = ttp
        data['incidents'][ttp.title] = []

    observables = {}
    for observable in stix_package.observables.observables:
        observables[observable.id_] = observable

    for incident in stix_package.incidents:
        ip = observables[incident.related_observables[0].item.idref].object_.properties.address_value.value
        ttp = ttps[incident.leveraged_ttps[0].item.idref]
        time = incident.time.first_malicious_action.value.isoformat()

        data['incidents'][ttp.title].append({
            'ip': ip,
            'time': time
        })

    print(data)

if __name__ == '__main__':
    try:
        fname = sys.argv[1]
    except:
        exit(1)

    fd = open(fname)
    stix_pkg = STIXPackage.from_xml(fd)

    parse_stix(stix_pkg)
