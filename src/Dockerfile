# syntax=docker/dockerfile:1.3

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
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_inspector && conda clean -afy
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_services && conda clean -afy
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_simulator && conda clean -afy

# update and install any new (i.e. pip) dependencies from environment.yaml
COPY --chown=user:user config/cfg/environment.yaml /app/environment.yaml
RUN --mount=type=cache,target=/opt/conda/pkgs conda env update -n autonomous_trust --file /app/environment.yaml
