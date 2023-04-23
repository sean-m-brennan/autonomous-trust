FROM continuumio/miniconda3

WORKDIR /app
SHELL ["/bin/bash", "-c"]
RUN apt-get update && apt-get install -y iproute2 iputils-ping iputils-arping iputils-tracepath && apt-get clean
COPY conda conda
RUN source conda/init_conda && create_env && conda clean -afy
SHELL ["conda", "run", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN source conda/init_conda && populate_env && conda clean -afy
COPY autonomous_trust autonomous_trust
RUN rm -rf autonomous_trust/etc autonomous_trust/var
CMD ["conda", "run", "--live-stream", "-n", "autonomous_trust", "python3", "-m", "autonomous_trust"]
