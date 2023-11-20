from setuptools import setup, find_packages

VERSION = '0.0.1' 
DESCRIPTION = 'Skydentity'
LONG_DESCRIPTION = 'Skydentity'

# Setting up
setup(
       # the name must match the folder name 'verysimplemodule'
        name="skydentity", 
        version=VERSION,
        author="Samyu Yagati",
        author_email="samyu@berkeley.edu",
        description=DESCRIPTION,
        long_description=LONG_DESCRIPTION,
        packages=find_packages(),
        install_requires=[],
)
