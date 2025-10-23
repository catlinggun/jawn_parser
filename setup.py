#!/usr/bin/env python3

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="jawn_parser",
    version="1.0.4",
    author="Dave Catling",
    author_email="dave.catling@phoenixops.io",
    description="A pentest scan parser, compatible with Nessus, Qualys, Nmap, and Burp",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=['XlsxWriter>=3.0.3',
        'beautifulsoup4>=4.14.2',
        'soupsieve>=2.8',
        'typing_extensions>=4.15.0',
        'wheel>=0.45.1',
        'xlsxwriter>=3.2.9',
    ],
    python_requires='>=3.9',
    entry_points={'console_scripts': ['jawn_parser=jawn_parser:main']}
)
