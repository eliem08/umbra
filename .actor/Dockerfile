# Apify Actor image for Umbra.
#
# Use Apify's official Python base image: it ships the Apify SDK (apify, crawlee,
# browserforge, pydantic, ...) pre-resolved to a mutually-compatible set. Building
# the SDK by hand on a bare python image produced version skews
# (pydantic >= 2.11, then crawlee<->browserforge), so we let Apify own that stack
# and only add Node (runtime Express discovery), git (gitUrl clone), and Umbra.
FROM apify/actor-python:3.12

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends git nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY . ./

# Install Umbra on top of the base SDK. Cap pydantic < 2.11 (a no-op on the base,
# which already ships a compatible pydantic) so none of Umbra's own dependencies
# upgrade it past the version crawlee/browserforge require.
RUN pip install --no-cache-dir -e . "pydantic>=2,<2.11"

# Batch run: scans input (gitUrl/path) and pushes results to the default dataset.
# Standby run: Apify sets APIFY_META_ORIGIN=STANDBY and a port; the entry then
# serves the MCP SSE server so it can be used via the Apify MCP marketplace.
CMD ["python", "-m", "umbra.apify.main"]
