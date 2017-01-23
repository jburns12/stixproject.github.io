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
        print("Confidence: " + indicator.confidence.value.value)

        for indicated_ttp in indicator.indicated_ttps:
            # Look up each TTP label
            ttp = stix_package.find(indicated_ttp.item.idref)

            for target in ttp.exploit_targets:
                et = stix_package.find(target.item.idref)

                for vuln in et.vulnerabilities:
                    print("Indicated TTP: " + ttp.title + ":" + vuln.cve_id)

        for tm in indicator.test_mechanisms:
            print("Producer: " + tm.producer.identity.name)
            print("Efficacy: " + tm.efficacy.value.value)
            for rule in tm.rules:
                print("Rule: " + rule.value)

if __name__ == '__main__':
    try:
        fname = sys.argv[1]
    except:
        exit(1)

    fd = open(fname)
    stix_pkg = STIXPackage.from_xml(fd)

    parse_stix(stix_pkg)
