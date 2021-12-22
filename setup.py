from typing import List

from setuptools import setup


def read_dependencies() -> List[str]:
    with open("./fastapi-keycloak/requirements.txt", "r+") as pip_file:
        requirements = pip_file.read()
    requirements_list = requirements.split('\n')
    return list(filter(lambda line: not (line.startswith('#') or line.startswith('-')) and line, requirements_list))


def read_description() -> str:
    with open("README.md", "r") as file:
        return file.read()


setup(
    name='fastapi-keycloak',
    packages=['fastapi-keycloak'],
    version='0.0.1a',
    license='apache-2.0',
    description='Keycloak API Client for integrating authentication and authorization with FastAPI',
    author='code_specialist',
    author_email='admin@code-specialist.com',
    url='https://github.com/code-specialist/fastapi-keycloak',
    download_url='https://github.com/code-specialist/fastapi-keycloak/archive/refs/tags/0.0.1a.tar.gz',
    long_description=read_description(),
    long_description_content_type='text/markdown',
    keywords=['Keycloak', 'FastAPI', 'Authentication', 'Authorization'],
    install_requires=read_dependencies(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Internet :: WWW/HTTP :: Session',
        'Framework :: FastAPI',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.8',
    ],
)
