import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="asn1util",
    version="0.0.1",
    author="CHEN Qiang",
    author_email="chenqiang@tsinghua.edu.cn",
    description="ASN.1 encoding/decoding utility",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
