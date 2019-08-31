import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="homescan",
    version="0.0.1",
    author="Si Dunford",
    author_email="dunford.sj+homescan@gmail.com",
    description="An ARP Presence detection system for the Home that publishes on MQTT.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Scaremonger/homescan",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
