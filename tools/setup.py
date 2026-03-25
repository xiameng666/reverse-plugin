from setuptools import setup, find_packages

setup(
    name="svcMonitor",
    version="0.1.0",
    packages=find_packages(),
    py_modules=["svcMonitor_cli"],
    install_requires=["click>=8.0"],
    entry_points={
        "console_scripts": [
            "svcMonitor=svcMonitor_cli:cli",
        ],
    },
    python_requires=">=3.8",
)
