# h4k — Metasploit automation lab (school cybersecurity project)
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV MSF_HOST=127.0.0.1 \
    MSF_PORT=55553 \
    MSF_PASSWORD=h4k_msf_rocks \
    TOR_PORT=9050 \
    API_PORT=3137

LABEL org.opencontainers.image.title="h4k" \
      org.opencontainers.image.description="Metasploit Framework automation tool (web UI -> API -> MSFRPC)" \
      org.opencontainers.image.source="https://github.com/Greg-2600/h4k"

# Base tooling + postgres + anonymization + dns recon deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates wget \
    postgresql postgresql-contrib \
    tor proxychains4 \
    python3 python3-pip python3-venv python3-dev \
    dnsutils whois prips iputils-ping \
    nmap whatweb arp-scan \
    && rm -rf /var/lib/apt/lists/*

# Rapid7 official Metasploit apt repository
RUN curl https://apt.metasploit.com/metasploit-framework.gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit-framework.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# Python automation stack (container images: break-system-packages is fine)
RUN python3 -m pip install --break-system-packages --no-cache-dir \
    pymetasploit3 fastapi uvicorn

WORKDIR /opt/h4k
COPY api /opt/h4k/api
COPY web /opt/h4k/web
COPY scripts /opt/h4k/scripts
COPY data /opt/h4k/data
COPY README.md /opt/h4k/README.md

# Proxychains config -> tor SOCKS (mirror of Greg-2600/proxy_scan)
RUN printf 'strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\nsocks5 127.0.0.1 9050\n' > /etc/proxychains.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/h4k/scripts/*.sh

EXPOSE 3137 55553

ENTRYPOINT ["/entrypoint.sh"]
