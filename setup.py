"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""
import os

from setuptools import setup, find_packages

# pylint: disable=redefined-builtin

here = os.path.abspath(os.path.dirname(__file__))  # pylint: disable=invalid-name

with open(os.path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()  # pylint: disable=invalid-name

setup(
    name='gsutilwrap',
    version='1.1.1',
    description='wraps gsutil, a command-line interface to Google Cloud Storage.',
    long_description=long_description,
    url='https://github.com/Parquery/gsutilwrap',
    author='Marko Ristin and Adam Radomski',
    author_email='marko@parquery.com',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='Google cloud storage gcloud gsutil deployment wrap',
    packages=find_packages(exclude=['tests']),
    install_requires=None,
    extras_require={
        'dev': ['mypy==0.600', 'pylint==1.8.4', 'yapf==0.20.2', 'tox>=3.0.0'],
        'test': ['tox>=3.0.0']
    },
    py_modules=['gsutilwrap'],
    package_data={"gsutilwrap": ["py.typed"]},
)
