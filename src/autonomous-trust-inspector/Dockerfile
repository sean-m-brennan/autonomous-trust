FROM autonomous-trust

WORKDIR /app
COPY requirements.txt requirements.txt
COPY pyproject.toml pyproject.toml
COPY autonomous_trust autonomous_trust
RUN pip install --no-cache-dir -e .

CMD ["sh", "-c", "conda run --live-stream -n autonomous_trust python3 -m autonomous_trust.inspector"]
