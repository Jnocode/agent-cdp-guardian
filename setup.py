from setuptools import setup, find_packages

setup(
    name="agent-cdp-guardian",
    version="0.1.0",
    packages=find_packages(include=["agent_cdp_guardian*"]),
    python_requires=">=3.8",
)
