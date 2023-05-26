FROM continuumio/miniconda3

WORKDIR /app
SHELL ["/bin/bash", "-c"]
RUN apt-get update && \
    apt-get install -y curl build-essential iproute2 iputils-ping iputils-arping iputils-tracepath && \
    apt-get clean

RUN mkdir conda
COPY conda/defaults conda/defaults
COPY conda/env conda/env
RUN source conda/env/create_conda_env && create_env && conda clean -afy
COPY conda/extra conda/extra
RUN source conda/extra/populate_conda_env && populate_env && conda clean -afy
COPY conda/rust conda/rust
RUN source conda/rust/add_rust_to_env && init_rust

SHELL ["conda", "run", "--live-stream", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install pydevd-pycharm
COPY pyproject.toml pyproject.toml
COPY rust rust
COPY autonomous_trust autonomous_trust
RUN rm -rf autonomous_trust/etc autonomous_trust/var
RUN maturin develop

ENV AUTONOMOUS_TRUST_ARGS=""
CMD ["sh", "-c", "conda run --live-stream -n autonomous_trust python3 -m autonomous_trust $AUTONOMOUS_TRUST_ARGS"]
