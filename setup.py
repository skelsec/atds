from setuptools import setup, find_packages
import re

VERSIONFILE="atds/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


setup(
	name="atds",
	version=verstr,
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",
	description="Python library to play with MS SQL Server",
	long_description="Python library to play with MS SQL Server",
	url="https://github.com/skelsec/atds",
	packages=find_packages(exclude=["tests*"]),	
	include_package_data=True,
	python_requires='>=3.8',
	classifiers=[
		"Programming Language :: Python :: 3.8",
		"Programming Language :: Python :: 3.9",
		"Programming Language :: Python :: 3.10",
		"Programming Language :: Python :: 3.11",
		"Programming Language :: Python :: 3.12",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'asyauth>=0.0.22',
		'asysocks>=0.2.11',
		'prompt-toolkit>=3.0.2',
		'wcwidth',
		'tabulate',
		'aiosmb>=0.4.11',
	],
	entry_points={
		'console_scripts': [
			'atds-client = atds.examples.tdsclient:main',
		],
	}
)
