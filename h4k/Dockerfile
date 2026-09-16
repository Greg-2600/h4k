# h4k — Metasploit lab container (school cybersecurity project)
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="h4k" \
      org.opencontainers.image.description="Metasploit Framework lab for automated testing of authorized lab machines"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gnupg ca-certificates \
    nmap iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Rapid7 official Metasploit apt repository
RUN curl https://apt.metasploit.com/metasploit-framework.gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ buster main" \
        > /etc/apt/sources.list.d/metasploit-framework.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/scripts

CMD ["bash"]
