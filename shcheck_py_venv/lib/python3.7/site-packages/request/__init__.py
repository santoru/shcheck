#!/usr/bin/env python
from get import GET
from post import POST

__all__ = ["REQUEST"]


def _request():
    kwargs = dict()
    kwargs.update(GET)
    kwargs.update(POST)
    return kwargs


REQUEST = _request()
