""" Tool Setup """
# !/usr/bin/env python3

# shcheck - Security headers check!
# Copyright (C) 2019-2021  santoru
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup

PACKAGE_NAME = "shcheck"
VERSION = "1.5.4"

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


def parse_requirements(filename):
    """Load requirements from a pip requirements file."""
    lineiter = (line.strip() for line in open(filename))
    return [line for line in lineiter if line and not line.startswith("#")]


if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        author="santoru",
        author_email="santoru@pm.me",
        description="A basic tool to check security headers of a website",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/santoru/shcheck",
        scripts=[
            "shcheck.py",
        ],
        python_requires='>=3'
    )
