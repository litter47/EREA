"""Runtime Docker image builder for sandboxed exploit execution.

Provides a pre-built Docker image (based on ubuntu:22.04) that contains
all common toolchains and runtimes needed for exploit verification.
"""

from __future__ import annotations

import io

import docker
from docker.models.images import Image
from docker.errors import DockerException, ImageNotFound

RUNTIME_DOCKERFILE = r"""FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    openjdk-17-jdk \
    maven \
    golang-go \
    gcc \
    g++ \
    gdb \
    nodejs \
    npm \
    curl \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python packages
RUN pip3 install --no-cache-dir \
    requests \
    pwntools \
    pyyaml \
    paramiko \
    httpx

RUN ln -sf /usr/bin/python3 /usr/bin/python

WORKDIR /exp
CMD ["/bin/bash"]
"""


def build_runtime_image(
    client: docker.DockerClient,
    image_name: str = "eva-runtime:latest",
) -> Image:
    """Build the runtime Docker image from the inline Dockerfile.

    Args:
        client: An authenticated Docker client instance.
        image_name: Tag to assign to the built image.

    Returns:
        The built Image object.

    Raises:
        docker.errors.BuildError: If the image build fails.
        docker.errors.DockerException: For other Docker-related errors.
    """
    image, build_logs = client.images.build(
        fileobj=io.BytesIO(RUNTIME_DOCKERFILE.encode("utf-8")),
        tag=image_name,
        rm=True,
        forcerm=True,
        pull=True,
    )
    return image


def ensure_runtime_image(
    client: docker.DockerClient,
    image_name: str = "eva-runtime:latest",
) -> bool:
    """Ensure the runtime Docker image exists, building it if necessary.

    Args:
        client: An authenticated Docker client instance.
        image_name: Tag of the image to check / build.

    Returns:
        True if the image is ready (found or freshly built), False on failure.
    """
    try:
        client.images.get(image_name)
        return True
    except ImageNotFound:
        pass
    except DockerException:
        pass

    try:
        build_runtime_image(client, image_name=image_name)
        return True
    except (docker.errors.BuildError, DockerException):
        return False
