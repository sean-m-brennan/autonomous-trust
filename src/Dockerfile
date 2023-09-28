# syntax=docker/dockerfile:1.3

# Runs pre-built AutonomousTrust subpackages

# Prerequisites: (build from repo base dir, context is src)
#   docker build -t package-builder -f src/Dockerfile-build src
#   docker run --rm -u $(id -u):$(id -g) -v src/autonomous-trust-inspector:/build/src -v src/dist:/build/dist -it package-builder
#   docker run --rm -u $(id -u):$(id -g) -v src/autonomous-trust-services:/build/src -v src/dist:/build/dist -it package-builder
#   docker run --rm -u $(id -u):$(id -g) -v src/autonomous-trust-simulator:/build/src -v src/dist:/build/dist -it package-builder
#   docker build -t autonomous-trust-full -f src/Dockerfile src
# Run like:
#   docker run --rm -u $(id -u):$(id -g) -v examples/requestor/requestor.py:/app/requestor.py e AUTONOMOUS_TRUST_EXE=requestor.py -it autonomous-trust-active-devel

FROM autonomous-trust

WORKDIR /app
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_inspector && conda clean -afy
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_services && conda clean -afy
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_simulator && conda clean -afy

ENV AUTONOMOUS_TRUST_EXE=""
CMD ["sh", "-c", "conda run --live-stream -n autonomous_trust python3 $AUTONOMOUS_TRUST_EXE"]
