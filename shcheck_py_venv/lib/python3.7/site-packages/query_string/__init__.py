#!/usr/bin/env python
try:
    from urlparse import parse_qs
except ImportError:
    from urllib.parse import parse_qs
import public


def _parse_qs(query):
    kwargs = dict()
    for k, v in parse_qs(query).items():
        if len(v) == 1:
            v = v[0]
        kwargs[k] = v
    return kwargs


@public.add
def query_string(string):
    """return dict with query string data. deprecated"""
    if not string:
        return dict()
    if "?" in string:
        qs = string.split("?")[1]
    else:
        qs = string
    if "#" in qs:
        qs = qs.split("#")[0]
    return _parse_qs(qs)

@public.add
def parse(string):
    """return dict with query string data"""
    if not string:
        return dict()
    if "?" in string:
        qs = string.split("?")[1]
    else:
        qs = string
    if "#" in qs:
        qs = qs.split("#")[0]
    return _parse_qs(qs)
