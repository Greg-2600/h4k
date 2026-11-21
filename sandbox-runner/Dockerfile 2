# h4k sandbox runner — isolated tool execution with rlimits.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    H4K_SANDBOX_PORT=9099 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 ca-certificates \
      nmap masscan arp-scan dnsutils curl \
      hydra ncrack john \
      smbclient ldap-utils \
      netcat-openbsd iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin sandbox

COPY runner.py /opt/sandbox/runner.py
RUN chmod 0755 /opt/sandbox/runner.py

USER sandbox
WORKDIR /home/sandbox
EXPOSE 9099

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -sf http://127.0.0.1:9099/health || exit 1

ENTRYPOINT ["python3", "/opt/sandbox/runner.py"]
