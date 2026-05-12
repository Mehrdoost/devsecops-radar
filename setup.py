from setuptools import setup, find_packages

setup(
    name='devsecops-radar',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask',
        'semgrep',
        'pyyaml'
    ],
    entry_points={
        'console_scripts': [
            'devsecops-radar=devsecops_radar.cli.scanner:main',
            'devsecops-radar-web=devsecops_radar.web.app:start_server'
        ]
    }
)