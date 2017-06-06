import setuptools
from safetyfirst.version import Version

install_requires = [
    'pytest',
    'pytest-cov',
    'ndg-httpsclient',
    'pyopenssl',
    'pyasn1'
]

setuptools.setup(
    name='safetyfirst',
    version=Version('1.0.0').number,
    description='Python SSL Checker',
    long_description=open('README.md').read().strip(),
    author='Robert Hoppe',
    author_email='robert.hoppe@nodemash.com',
    url='http://nodemash.com',
    py_modules=['safetyfirst'],
    install_requires=install_requires,
    license='MIT',
    zip_safe=False,
    keywords='ssl certificate validation',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Utilities'
    ],
    entry_points={
        'console_scripts': [
            'safety_ssl_check = safetyfirst.utilities.ssl_check:launch_new_instance'
        ]
    }
)
