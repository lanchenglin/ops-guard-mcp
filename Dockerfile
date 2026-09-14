FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp \
    OPS_GUARD_CONFIG=/etc/ops-guard/ops-guard.toml

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 opsguard \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp --shell /usr/sbin/nologin opsguard

WORKDIR /opt/ops-guard

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY scripts/dingtalk-discover-context.py ./scripts/dingtalk-discover-context.py

RUN python -m pip install --upgrade pip \
    && python -m pip install '.[dingtalk]' \
    && mkdir -p /var/lib/ops-guard /etc/ops-guard /etc/ops-guard/ssh /tmp/ops-guard \
    && chown -R 10001:10001 /var/lib/ops-guard /etc/ops-guard /tmp/ops-guard /opt/ops-guard

USER 10001:10001

CMD ["ops-guard-daemon", "--config", "/etc/ops-guard/ops-guard.toml"]
