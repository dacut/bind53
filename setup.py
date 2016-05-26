#!/usr/bin/env python
# pylint: disable=C0111
from __future__ import absolute_import, division, print_function
from setuptools import setup

setup(
    name="bind53",
    version="0.1",
    py_modules=["bind53"],
    scripts=["bin/bind53"],
    install_requires=["boto3>=1.0", "dnspython>=1.13.0", "six>=1.10.0"],

    # PyPI information
    author="David Cuthbert",
    author_email="cuthbert@amazon.com",
    description="Convert Route53 resource record sets to bind configuration",
    license="Apache",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords=['aws', 'dns', 'bind', 'route53'],
    url="https://github.com/dacut/bind53",
    zip_safe=False,
)
