from typing import List

import setuptools as setuptools
from setuptools import setup


def read_description() -> str:
    with open("../README.md", "r") as fh:
        return fh.read()


def read_dependencies() -> List[str]:
    with open("requirements.txt", "r+") as pip_file:
        requirements = pip_file.read()
    requirements_list = requirements.split('\n')
    return list(filter(lambda line: not (line.startswith('#') or line.startswith('-')) and line, requirements_list))


def get_packages() -> List[str]:
    all_packages = setuptools.find_packages()
    return [package for package in all_packages]


setup(
    name='fastapi-keycloak',
    version='0.0.1a',
    packages=get_packages(),
    description='Keycloak integration for FastAPI',
    long_description=read_description(),
    long_description_content_type="text/markdown",
    url='https://github.com/code-specialist/fastapi-keycloak',
    install_requires=read_dependencies(),
    python_requires='>=3.8',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
