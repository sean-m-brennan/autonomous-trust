# syntax=docker/dockerfile:1.3

# Runs pre-built AutonomousTrust

# Prerequisites: (build from repo base dir, context is src)
#   docker build -t package-builder -f src/Dockerfile-build src
#   docker run --rm -u $(id -u):$(id -g) -v src/autonomous-trust:/build/src -v src/dist:/build/dist -it package-builder
#   docker build -t autonomous-trust -f src/autonomous-trust/Dockerfile src

FROM continuumio/miniconda3

WORKDIR /app
SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    apt-get install -y iproute2 iputils-ping iputils-arping iputils-tracepath sudo && \
    apt-get clean

#RUN useradd -U user -d /app
RUN echo "ALL            ALL = (ALL) NOPASSWD: ALL" >>/etc/sudoers
#RUN chown -R user:user /app
#COPY --chown=user:user autonomous-trust/.bashrc /app/.bashrc

RUN conda config --add channels conda-forge
RUN conda update -y -n base conda
RUN conda create -n autonomous_trust python=3.10 && conda clean -afy

COPY autonomous-trust/entrypoint.sh /bin/entrypoint.sh
ENV ROUTER="172.17.0.1"
ENTRYPOINT ["/bin/entrypoint.sh"]

SHELL ["conda", "run", "--live-stream", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install pydevd-pycharm
RUN --mount=source=dist,target=/app/dist \
    conda install -y -c file:///app/dist autonomous_trust && conda clean -afy

#ENV AUTONOMOUS_TRUST_ROOT=/app
ENV AUTONOMOUS_TRUST_ARGS="--live"
CMD ["/bin/bash", "-c", "conda run --live-stream -n autonomous_trust python3 -m autonomous_trust $AUTONOMOUS_TRUST_ARGS || /bin/bash"]
