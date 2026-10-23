# h4k — Metasploit automation lab (school cybersecurity project)
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
# AI triage: any OpenAI-compatible gateway; the opencode relay is keyless
# (H4K_AI_KEYLESS=1 + H4K_AI_URL=http://127.0.0.1:3777/... with relay up)
ENV MSF_HOST=127.0.0.1 \
    MSF_PORT=55553 \
    MSF_PASSWORD=h4k_msf_rocks \
    TOR_PORT=9050 \
    API_PORT=3137 \
    PYTHONUNBUFFERED=1 \
    H4K_LOG_LEVEL=INFO \
    H4K_AI_PROVIDER=openai_compatible \
    H4K_AI_KEYLESS=1 \
    H4K_AI_MODEL=opencode/beam-free

LABEL org.opencontainers.image.title="h4k" \
      org.opencontainers.image.description="Metasploit Framework automation tool (web UI -> API -> MSFRPC)" \
      org.opencontainers.image.source="https://github.com/Greg-2600/h4k"

# Base tooling + postgres + anonymization + dns recon deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates wget \
    postgresql postgresql-contrib \
    tor proxychains4 \
    python3 python3-pip python3-venv python3-dev \
    dnsutils whois prips iputils-ping traceroute dnstracer \
    nmap whatweb arp-scan \
    masscan tcpdump tshark netcat-openbsd socat iproute2 \
hydra ncrack john sqlmap \
    dirb gobuster ffuf \
    smbclient smbmap dnsenum dnsrecon \
    ldap-utils samba-common-bin \
    bettercap aircrack-ng sshuttle \
    git \
    openjdk-17-jre-headless \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# chisel (TCP pivoting) — not in Debian apt; grab the release binary
RUN CHISEL_VER=$(\
      curl -s https://api.github.com/repos/jpillora/chisel/releases/latest \
      | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4) \
    && curl -sSfL "https://github.com/jpillora/chisel/releases/download/${CHISEL_VER}/chisel_${CHISEL_VER#v}_linux_amd64.gz" \
       -o /tmp/chisel.gz \
    && gunzip -f /tmp/chisel.gz && mv /tmp/chisel /usr/local/bin/chisel \
    && chmod +x /usr/local/bin/chisel

# impacket (secretsdump, wmiexec, GetNPUsers...) — powershell/AD RPC suite
RUN python3 -m pip install --break-system-packages --no-cache-dir impacket \
  && for s in secretdump secretsdump wmiexec smbexec GetNPUsers getTGT GetADUsers \
             mssqlclient smbclient; do \
       if [ -f "/usr/lib/python3/dist-packages/impacket/examples/${s}.py" ]; then \
         ln -sf "/usr/lib/python3/dist-packages/impacket/examples/${s}.py" "/usr/local/bin/${s}.py"; \
       fi; \
     done

# nikto not packaged in Debian; install via git (widely used web vuln scanner)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Nuclei — fast template-based vulnerability scanner
RUN apt-get update && apt-get install -y --no-install-recommends unzip && rm -rf /var/lib/apt/lists/* \
    && NUCLEI_VER=$(\
      curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4) \
    && curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_VER#v}_linux_amd64.zip" \
       -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip

# OWASP ZAP (Zed Attack Proxy) — web app scanner with active/passive scan,
# spider, AJAX spider, fuzzer, API. Headless mode for automation.
RUN ZAP_VER="2.17.0" \
    && curl -sSfL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VER}/ZAP_${ZAP_VER}_Linux.tar.gz" \
       -o /tmp/zap.tar.gz \
    && tar -xzf /tmp/zap.tar.gz -C /opt \
    && mv /opt/ZAP_${ZAP_VER} /opt/zap \
    && ln -s /opt/zap/zap.sh /usr/local/bin/zap \
    && rm /tmp/zap.tar.gz

# Rapid7 official Metasploit apt repository
RUN curl https://apt.metasploit.com/metasploit-framework.gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit-framework.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# Python automation stack (container images: break-system-packages is fine)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/* \
    && python3 -m pip install --break-system-packages --no-cache-dir \
    pymetasploit3 fastapi uvicorn python-multipart semgrep \
    python-owasp-zap-v2.4 \
    mitm6 \
    responder3 \
    bloodhound

# SCA / supply-chain tools: osv-scanner (Google) validates a repo/SBOM against
# the OSV vulnerability DB; trivy (Aqua) can emit a CycloneDX SBOM.
RUN OSV_VER=$(\
      curl -s https://api.github.com/repos/google/osv-scanner/releases/latest \
      | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4) \
    && curl -sSfL "https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_linux_amd64" \
       -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin


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
