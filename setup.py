from setuptools import setup, find_packages

setup(
    name="eva-agent",
    version="0.1.0",
    description="EVA-Agent: Exploit Verification Agent Platform",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.27.0",
        "python-multipart>=0.0.9",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "docker>=7.0.0",
        "asyncssh>=2.14.0",
        "httpx>=0.26.0",
        "openai>=1.12.0",
        "pyyaml>=6.0.1",
        "aiofiles>=23.2.1",
    ],
)
