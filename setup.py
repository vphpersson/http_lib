from setuptools import setup, find_packages

setup(
    name='http_lib',
    version='0.11',
    packages=find_packages(),
    install_requires=[
        'git+https://github.com/declaresub/abnf.git#egg=abnf'
    ]
)
