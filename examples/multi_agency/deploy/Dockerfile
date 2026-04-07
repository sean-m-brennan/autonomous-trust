# syntax=docker/dockerfile:1.3
# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************

# Civilian disaster response demo image.
# Layers the demo code on top of the full AT development stack.
#
# Prerequisites:
#   The base image must be built first:
#     docker build -t autonomous-trust-devel -f src/autonomous-trust/Dockerfile-devel .
#     docker build -t autonomous-trust-full-devel -f src/Dockerfile-devel .
#
# Build (from repo root):
#   docker build -t at-civilian-demo -f examples/multi_agency/deploy/Dockerfile .

ARG REGISTRY_URL
ARG IMAGE_TAG
FROM ${REGISTRY_URL}autonomous-trust-full-devel${IMAGE_TAG}

USER root
# plotly for dashboard charts (may already be in base image)
SHELL ["conda", "run", "--live-stream", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install plotly pyyaml 2>/dev/null || true
USER user

WORKDIR /app

# Copy multi-agency demo code
COPY --chown=user:user examples/multi_agency /app/examples/multi_agency

# Ensure examples/ is importable
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Default: show help
CMD ["echo", "Usage: set AUTONOMOUS_TRUST_EXE to participant.py or coordinator.py"]
