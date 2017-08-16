#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2016 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import hjson, json
import os
import sys
import requests

class DotDict(dict):
    '''dict.item notation for dict()'s'''
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

def get_percentage(stats, attr):
    if not 'percent' in stats[attr].keys():
        raise KeyError("Need ('nr', 'percent') tuple present to get percentage")

    p = stats[attr].nr * 100 / stats.total
    stats[attr].percent = p
    return stats

def main():
    #Configuration loading
    with open('rrastats.json') as fd:
        config = DotDict(hjson.load(fd))

    if config == None:
        print("No configuration file 'rrastats.json' found.")
        sys.exit(1)

    if ("x509cert" in config.keys()):
        v = config.x509cert
    else:
        v = True
    headers = {'SERVICEAPIKEY': config.apikey}
    r = requests.get("{}/api/v1/risks".format(config.host), verify=v, headers=headers)

    with open('eis_auto_out.json', 'w') as fd:
        fd.write(r.text)

    if (r.status_code != 200):
        raise ApiError("Could not talk to EIS Host {} HTTP errors GET /api/v1/risks: {}".format(config.host, r.status_code))

    stats = DotDict({'total': -1,
                'services_linked': {'nr':-1, 'percent':-1},
                'with_data_dict_and_default_data': {'nr': -1, 'percent': -1},
                'have_assets': {'nr': -1, 'percent': -1}})

    risks = r.json()['risks']
    for risk in risks:
        risk = DotDict(risk)
        median_risk_label = risk.risk.median_label
        rra = risk.rra.rra_details.details
        rraeis = risk.rra
        try:
            if (len(rra.metadata.linked_services) > 0):
                stats.services_linked.nr = stats.services_linked.nr + 1
                #print(rra.metadata.service)
        except KeyError:
            pass
        try:
            #If default data is missing then the data dict structure as well, so that checks both
            if (len(rra.data.default) > 1):
                stats.with_data_dict_and_default_data.nr = stats.with_data_dict_and_default_data.nr +1
        except KeyError:
            pass
        try:
            asgrp = rraeis.asset_groups
            stats.have_assets.nr = stats.have_assets.nr + 1
            #print(rra.metadata.service)
        except KeyError:
            pass
        stats.total = stats.total + 1

    stats = get_percentage(stats, 'services_linked')
    stats = get_percentage(stats, 'with_data_dict_and_default_data')
    stats = get_percentage(stats, 'have_assets')

    print(stats)

if __name__ == "__main__":
    main()
