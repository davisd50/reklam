from setuptools import setup, find_packages


version = '0.0.1'

tests_require=[
    'pytest',
    'pytest-cov'
],

setup(name='reklam',
      version=version,
      description="A ZFS volume space reclamation tool",
      long_description=open("README.md").read() + "\n" +
                       open("HISTORY.txt").read(),
      # Get more strings from
      # http://pypi.python.org/pypi?:action=list_classifiers
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Framework :: Pyramid',
        'Intended Audience :: Developers',
        'License :: Other/Proprietary License',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
      ],
      author='David Davis',
      author_email='davisd50@gmail.com',
      url='https://github.com/davisd50/reklam',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=[],
      include_package_data=True,
      package_data = {
          '': ['*.zcml', '*.xml', '*.yml', '*.yaml']
        },
      zip_safe=False,
      install_requires=[
          'setuptools',
          'sparc.cli',
          'sparc.config'

      ],
      extras_require={
            'testing': tests_require,
      },
      entry_points={
          'console_scripts':['reklam=reklam:main']
          },
      )
