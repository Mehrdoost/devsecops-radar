from setuptools import setup, find_packages

setup(
    name='devsecops-radar',
    version='0.1.0',
    author='Mehrdoost',
    author_email='mehrdoost@users.noreply.github.com',
    url='https://github.com/Mehrdoost/devsecops-radar',
    description='Unified CI/CD Security Dashboard — Pipeline Sentinel',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask',
        'semgrep',
        'pyyaml',
        'requests'
    ],
    entry_points={
        'console_scripts': [
            'devsecops-radar=devsecops_radar.cli.scanner:main',
            'devsecops-radar-web=devsecops_radar.web.app:start_server'
        ]
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.12',
    ],
)