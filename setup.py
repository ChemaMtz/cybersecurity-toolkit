from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cybersecurity-toolkit",
    version="1.0.0",
    author="Cybersecurity Toolkit Team",
    author_email="security@example.com",
    description="Suite modular de herramientas de ciberseguridad para auditoría de red, análisis de seguridad y análisis forense.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/cybersecurity-toolkit",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cyber-portscan=tools.network.port_scanner:main",
            "cyber-netmap=tools.network.network_mapper:main",
            "cyber-sniff=tools.network.packet_sniffer:main",
            "cyber-pwd-check=tools.security.password_analyzer:main",
            "cyber-hash-crack=tools.security.hash_cracker:main",
            "cyber-malware-scan=tools.security.malware_detector:main",
            "cyber-log-audit=tools.forensics.log_analyzer:main",
            "cyber-fim=tools.forensics.file_integrity:main",
        ],
    },
)
