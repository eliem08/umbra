# Apify Actor image for Umbra.
# Includes Node (for runtime-assisted Express discovery) and git (for --since /
# cloning targets). Installs the package plus the Apify SDK + uvicorn.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Install Umbra + the Apify SDK in a single resolution. pydantic is capped below
# 2.11 because crawlee (a transitive Apify SDK dependency) fails to import on
# pydantic >= 2.11 ("cannot specify both default and default_factory").
RUN pip install --no-cache-dir -e . "apify>=2,<3" uvicorn "pydantic>=2,<2.11"

# Batch run: scans input and pushes results to the default dataset.
# Standby run: Apify sets APIFY_META_ORIGIN=STANDBY and a port; the entry then
# serves the MCP SSE server so it can be used via the Apify MCP marketplace.
CMD ["python", "-m", "umbra.apify.main"]
