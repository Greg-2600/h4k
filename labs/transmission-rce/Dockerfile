FROM alpine:3.20

# transmission-rce lab
#
# A deliberately misconfigured Transmission daemon used to demonstrate the
# full "unauthenticated RPC -> arbitrary file write -> remote code execution"
# chain end to end:
#
#   1. the RPC interface has NO authentication and NO IP whitelist
#   2. a .torrent can be added by URL (the daemon fetches it from the
#      attacker) and its payload is written to any writable directory
#   3. when that torrent completes, Transmission runs the configured
#      "script-torrent-done" hook -> the written file is executed
#
# The hook points at /downloads/payload.sh, which does not exist yet: the
# attacker has to deliver it first (step 2), which is exactly the chain.
#
# Nothing here leaves the lab: it is a teaching target, like vulnlab.
ENV HOME=/var/lib/transmission
RUN apk add --no-cache transmission-daemon supervisor python3 busybox

# the transmission-daemon package already creates the user/group; make the
# setup idempotent so the image builds on top of it
RUN addgroup -S transmission 2>/dev/null || true; \
    adduser -S -D -H -h /var/lib/transmission -G transmission transmission 2>/dev/null || true; \
    mkdir -p /downloads /var/lib/transmission /etc/transmission-daemon; \
    chown -R transmission:transmission /downloads /var/lib/transmission

# The vulnerable configuration:
#   * rpc-authentication-required = false   -> no credentials needed
#   * rpc-whitelist-enabled     = false   -> any host may talk to it
#   * script-torrent-done-*      = armed    -> the hook runs on completion
COPY settings.json /etc/transmission-daemon/settings.json
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 9091 8080
CMD ["supervisord", "-c", "/etc/supervisord.conf"]
