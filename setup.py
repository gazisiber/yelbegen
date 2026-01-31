from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="yelbegen",
    version="1.0.0",
    author="Security Research Team",
    description="Professional TUI-based OSINT reconnaissance tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/yelbegen",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "yelbegen=yelbegen.main:main",
        ],
    },
)
