# Apify Actor image for Umbra.
#
# The entry (umbra/apify/main.py) talks to the Apify REST API directly via httpx
# and does NOT import the Apify Python SDK, so this image only needs Umbra's own
# (clean, known-good) dependencies — no crawlee/browserforge/pydantic conflicts.
# Node is for runtime-assisted Express discovery; git is for the gitUrl clone.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git nodejs npm build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Install Umbra with the x402 extra so the payment gate can be enabled via env.
# build-essential covers any C-extension deps in the x402/web3 stack that lack wheels.
RUN pip install --no-cache-dir ".[x402]"

# Batch run: scans input (gitUrl/path) and pushes results to the default dataset.
# Standby run: APIFY_META_ORIGIN=STANDBY -> serves the MCP SSE server.
CMD ["python", "-m", "umbra.apify.main"]
