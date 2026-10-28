# Cathedral SN94 validator bootstrap image.
# Contains Ubuntu 24.04, /usr/bin/python3.12, the verified signed updater,
# the runtime release public key, and the stable floor. No validator release
# is baked in. Runtime PEX files download into the named volume.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl \
        python3.12 \
        python3.12-venv \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/bin/python3.12 \
    && test -x /usr/bin/setpriv \
    && useradd --system --uid 910 --gid nogroup \
        --home-dir /var/lib/cathedral-validator \
        --shell /usr/sbin/nologin \
        cathedral-validator \
    && mkdir -p /var/lib/cathedral /run/cathedral

# Build context is the repository root. The installer module is loaded as a
# library so the image can skip systemd host activation.
COPY deploy/validator-update/install_updater_bundle.py \
    /src/deploy/validator-update/install_updater_bundle.py
COPY deploy/validator-docker/install_image_bootstrap.py \
    /src/deploy/validator-docker/install_image_bootstrap.py

RUN /usr/bin/python3.12 /src/deploy/validator-docker/install_image_bootstrap.py \
        --root / \
        --staging /tmp/cathedral-bootstrap \
        --python /usr/bin/python3.12 \
    && rm -rf /tmp/cathedral-bootstrap /src

COPY deploy/validator-docker/container_supervisor.py \
    /usr/local/sbin/cathedral-validator-supervisor
COPY deploy/validator-docker/container_update.py \
    /usr/local/lib/cathedral-container/container_update.py
COPY deploy/validator-update/cathedral-validator-status \
    /usr/local/sbin/cathedral-validator-status
COPY deploy/validator-docker/record-failed-write \
    /usr/local/sbin/cathedral-validator-record-failed-write

RUN chmod 0755 \
        /usr/local/sbin/cathedral-validator-supervisor \
        /usr/local/sbin/cathedral-validator-status \
        /usr/local/sbin/cathedral-validator-record-failed-write \
        /usr/local/lib/cathedral-container/container_update.py

VOLUME ["/var/lib/cathedral"]

STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/bin/python3.12", "/usr/local/sbin/cathedral-validator-supervisor"]
