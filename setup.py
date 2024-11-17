from setuptools import setup, find_packages

setup(
    name='pidnetdump',
    version='1.0.0',
    description='Real-time network packet monitoring for a specific PID',
    author='Cenab Batu Bora',
    author_email='batu.bora.tech@gmail.com',
    url='https://github.com/cenab/pidnetdump',
    packages=find_packages(),
    install_requires=[
        'psutil>=5.9.5',
        'scapy>=2.5.0',
        'setuptools>=65.5.0',
    ],
    python_requires='>=3.11',
    entry_points={
        'console_scripts': [
            'pidnetdump=pidnetdump.pidnetdump:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
)
