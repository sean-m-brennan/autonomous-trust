# syntax=docker/dockerfile:1.3
# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

# Runs pre-built AutonomousTrust subpackages

# Prerequisites: (build from repo base dir, context is src)
#   docker build -t package-builder -f src/Dockerfile-build src
#   docker run --rm -u $(id -u):$(id -g) -v $PWD/src/autonomous-trust-inspector:/build/src -v $PWD/src/dist/conda-repo:/build/dist -it package-builder
#   docker run --rm -u $(id -u):$(id -g) -v $PWD/src/autonomous-trust-services:/build/src -v $PWD/src/dist/conda-repo:/build/dist -it package-builder
#   docker run --rm -u $(id -u):$(id -g) -v $PWD/src/autonomous-trust-simulator:/build/src -v $PWD/src/dist/conda-repo:/build/dist -it package-builder
#   docker build -t autonomous-trust-full -f src/Dockerfile src
# Run like:
#   docker run --rm -u $(id -u):$(id -g) -v examples/requestor/requestor.py:/app/requestor.py e AUTONOMOUS_TRUST_EXE=requestor.py -it autonomous-trust-active-devel

ARG REGISTRY_URL
ARG IMAGE_TAG
FROM ${REGISTRY_URL}autonomous-trust${IMAGE_TAG}

WORKDIR /app
RUN --mount=source=src/dist/conda-repo,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_inspector && conda clean -afy
RUN --mount=source=src/dist/conda-repo,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_services && conda clean -afy
RUN --mount=source=src/dist/conda-repo,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_simulator && conda clean -afy

# g++ for a pip dep that has to compile at env-update time. pykcs11 is the case
# in hand: it publishes no Linux wheel for ANY version (PyPI index checked
# 2026-09-01 -- macOS and Windows only), so pip always builds its SWIG/C++
# extension from the sdist here, and the version pinned in
# config/cfg/environment.yml is floor-critical for that build (see the note
# beside it: anything below 1.5.19 no longer compiles with current SWIG). SWIG itself comes from pykcs11's own pip build
# isolation; only the compiler is missing -- the base image ships clang, not
# g++. Install it just for the build and purge it afterward so the release image
# stays lean: the compiled .so links only libstdc++6, which is part of the base
# runtime and is retained.
#
# Plain apt g++ is the right answer HERE and would be the wrong answer in the
# devel image, which is worth one line so the two are not "fixed" alike. This
# env holds no conda compiler package, so nothing exports CXX and setuptools
# falls back to what python's sysconfig names, which g++ satisfies. The devel
# env DOES hold gxx_linux-64, whose activation exports
# CXX=x86_64-conda-linux-gnu-c++ -- and when a `--prune` deleted that package
# while the variable stayed exported, the pip build went looking for a compiler
# that no longer existed (2026-09-01; see scripts/setup-dev.sh and the note
# beside the dep in config/cfg/environment.yml).
# update and install any new (i.e. pip) dependencies from environment.yml
COPY --chown=user:user config/cfg/environment.yml /app/environment.yml
RUN --mount=type=cache,target=/opt/conda/pkgs \
    (apt-get update -y -o Acquire::AllowInsecureRepositories=true || true) && \
    apt-get install -y --no-install-recommends --allow-unauthenticated g++ && \
    conda env update -n autonomous_trust --file /app/environment.yml && \
    apt-get purge -y --auto-remove g++ && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
