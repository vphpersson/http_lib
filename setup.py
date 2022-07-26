from setuptools import setup, find_packages

setup(
    name='http_lib',
    version='0.3',
    packages=find_packages(),
    install_requires=[
        'abnf_parse @ git+https://github.com/vphpersson/abnf_parse.git#egg=abnf_parse',
        'public_suffix @ git+https://github.com/vphpersson/public_suffix.git#egg=public_suffix'
    ]
)
