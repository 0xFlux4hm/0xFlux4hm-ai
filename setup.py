from setuptools import setup, find_packages

setup(
    name="flux-ai-router",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "flux=router:main"
        ]
    },
)
