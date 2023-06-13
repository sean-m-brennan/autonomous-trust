# syntax=docker/dockerfile:1.3

# Runs pre-built AutonomousTrust Inspector (useless without other AutonomousTrust instances)

# Prerequisites: (build from repo base dir, context is src)
#   docker build -t package-builder -f src/Dockerfile-build src
#   docker run --rm -u $(id -u):$(id -g) -v src/autonomous-trust-inspector:/build/src -v src/dist:/build/dist -it package-builder
#   docker build -t autonomous-trust-inspector -f src/autonomous-trust-inspector/Dockerfile src

FROM autonomous-trust

WORKDIR /app
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust_inspector && conda clean -afy

CMD ["sh", "-c", "conda run --live-stream -n autonomous_trust python3 -m autonomous_trust.inspector"]
