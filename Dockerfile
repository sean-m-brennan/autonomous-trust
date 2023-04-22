FROM continuumio/miniconda3:latest

WORKDIR /app
SHELL ["/bin/bash", "-c"]
COPY conda conda
COPY autonomous_trust autonomous_trust
COPY setup.py setup.py
RUN source conda/init_conda && create_env
RUN source conda/init_conda && populate_env
SHELL ["conda", "run", "-n", "autonomous_trust", "/bin/bash", "-c"]
RUN pip install -e .
ENV identifier 1  # FIXME random number
#CMD conda run -n autonomous_trust python3 -m autonomous_trust $identifier
ENTRYPOINT ["conda", "run", "-n", "--no-capture-output", "autonomous_trust", "python3 -m autonomous_trust"]