import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="makepw",
    version="2.1",
    author="Eric Hopper",
    author_email="hopper@omnifarious.org",
    description="Unique, secure passwords with no password database.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://bitbucket.org/Omnifarious/MakePW",
    packages=setuptools.find_packages(),
    py_modules=["makepw"],
    package_data={
        'makepw': ['wordlist.txt']
    },
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4",
    entry_points={
        'console_scripts': [
            "makepw = makepw:entrypoint",
            ],
        },
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Environment :: Console",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Topic :: Utilities",
        "Topic :: Security"
        ],
    )
