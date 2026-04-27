from setuptools import setup, find_packages

setup(
    name="mirage",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["boto3>=1.34.0", "click>=8.1.0"],
    entry_points={"console_scripts": ["mirage=mirage.cli:main"]},
    python_requires=">=3.10",
)
