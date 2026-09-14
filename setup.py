from setuptools import setup, find_packages

setup(
    name="kernelguard",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "kernelguard": ["ebpf/*.c", "policy.json"],
    },
    entry_points={
        "console_scripts": [
            "kernelguard=kernelguard.cli:main",
        ],
    },
)
