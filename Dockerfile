# No upstream CLI to wrap (unlike playwright-mcp-guarded/jenkins-mcp) --
# this talks SSH directly via asyncssh, so a plain Python base is enough.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml ./
COPY ssh_mcp ./ssh_mcp
RUN pip install --no-cache-dir .

# HOST_KEY_STORE_PATH's directory is created on startup (see hostkeys.py),
# but a named volume mounted there is what actually makes TOFU pins
# survive a container recreate -- see README.
ENV PORT=8080 \
    HOST_KEY_STORE_PATH=/data/host_keys.json

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=3)" || exit 1

ENTRYPOINT ["ssh-mcp"]
