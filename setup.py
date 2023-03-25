#!/usr/bin/env python3
from setuptools import setup, find_packages
# configure the setup to install from specific repos and users

DESC = 'Rapid proto typing framework for creating memory analysis overlays'
setup(name='overlay-prototyping',
      version='1.0',
      description=DESC,
      author='adam pridgen',
      author_email='dso@thecoverofnight.com',
      install_requires=[
                   ],
      packages=find_packages('overlay_prototyping'),
      package_dir={'': 'overlay_prototyping'},
      dependency_links=[],
)