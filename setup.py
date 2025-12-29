"""
Setup file for Andrea library
"""

from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='aquasec',
    version='0.7.0',
    author='Andrea Zorzetto',
    description='API client library for Aqua Security platform',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/andreazorzetto/aquasec-lib',
    packages=['aquasec'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires='>=3.7',
    install_requires=[
        'requests>=2.28.0',
        'prettytable>=3.5.0',
        'cryptography>=41.0.0',
        'inquirer>=3.1.0',
    ],
)