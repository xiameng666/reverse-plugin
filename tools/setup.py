from setuptools import setup, find_packages

setup(
    name="svcmon",
    version="0.1.0",
    packages=find_packages(),
    py_modules=["svcmon_cli"],
    install_requires=["click>=8.0"],
    entry_points={
        "console_scripts": [
            "svcmon=svcmon_cli:cli",
        ],
    },
    python_requires=">=3.8",
)
