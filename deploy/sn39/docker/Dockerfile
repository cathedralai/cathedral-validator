# SN39 relay validator image. Build context is the repo root (see docker-compose.yml).
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/cathedral-validator
COPY . /opt/cathedral-validator

# The relay validator: the [provenance] extra pulls the pinned bittensor 10.5 SDK,
# numpy, and — by design — the version-coupled cathedral-compute at a pinned sha, so
# the image is a coherent release set, not a floating checkout.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir '.[provenance]'

RUN chmod +x deploy/sn39/docker/entrypoint.sh

# Safe defaults: mainnet SN39, SHADOW (never broadcasts unless the operator opts in).
ENV CATHEDRAL_NETWORK=finney \
    CATHEDRAL_NETUID=39 \
    BT_WALLET_PATH=/root/.bittensor/wallets \
    CATHEDRAL_BROADCAST=0

ENTRYPOINT ["/opt/cathedral-validator/deploy/sn39/docker/entrypoint.sh"]
CMD ["validator"]
