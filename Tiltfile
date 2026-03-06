# Tiltfile for AutonomousTrust multi-node demo
# Usage: tilt up -- --num-nodes=4 [--exclude-logs=network] [--log-level=debug] [--backend=native|python]

# We only use docker_compose, not k8s -- allow whatever context is active
allow_k8s_contexts(k8s_context())

config.define_string("num-nodes")
config.define_string("exclude-logs")
config.define_string("log-level")
config.define_string("backend")
cfg = config.parse()
num_nodes = cfg.get("num-nodes", "2")
exclude_logs = cfg.get("exclude-logs", "network")
log_level = cfg.get("log-level", "info")
backend = cfg.get("backend", "native")

# Generate docker-compose.tilt.yaml for the requested number of nodes
local("python3 gen_compose.py " + num_nodes + " " + exclude_logs + " " + log_level + " " + backend, quiet=True, echo_off=True)

# Build args: pass through proxy env vars if set
build_args = {}
for var in ["http_proxy", "https_proxy", "no_proxy"]:
    val = os.getenv(var, "")
    if val:
        build_args[var] = val

# Auto-detect proxy CA cert: env var first, then well-known filesystem path
cert_content = os.getenv("CERT_CONTENT", "")
if not cert_content:
    cert_path = "/usr/local/share/ca-certificates/proxy-ca.crt"
    result = str(local("cat " + cert_path + " 2>/dev/null || true", quiet=True, echo_off=True))
    if result.strip():
        cert_content = result.strip()
if cert_content:
    build_args["CERT_CONTENT"] = cert_content

# Get version from git for C library build
git_version = str(local("git describe HEAD 2>/dev/null || echo unknown", quiet=True, echo_off=True)).strip()
git_version = git_version.removeprefix("v")
build_args["GIT_VERSION"] = git_version

# Select Dockerfile based on backend
if backend == "native":
    dockerfile = "src/autonomous-trust/Dockerfile-native"
else:
    dockerfile = "src/autonomous-trust/Dockerfile-lite"

# Build the image
docker_build(
    "autonomous-trust",
    ".",
    dockerfile=dockerfile,
    network="host",
    build_args=build_args,
)

# Load the generated compose file
docker_compose("docker-compose.tilt.yaml")

# Watch key source dirs for live rebuild triggers
watch_file("src/autonomous-trust/autonomous_trust")
watch_file("src/autonomous-trust/entrypoint.sh")
watch_file("src/protobuf")
if backend == "native":
    watch_file("src/c")
