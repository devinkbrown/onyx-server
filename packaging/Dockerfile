# Onyx Server — minimal, reproducible container image.
#
# The daemon is a single static x86_64-linux-musl binary with ZERO external
# dependencies, so the runtime image is just the binary + a quickstart config.
# The binary's provenance is anchored by dist/SHA256SUMS — anyone can rebuild it
# and confirm it byte-for-byte with `packaging/verify-release.sh`.
#
#   1. Build the verified artifact:   packaging/release.sh
#   2. Build the image:               docker build -f packaging/Dockerfile -t onyx-server:latest .
#   3. Run it:                        docker run --read-only --cap-drop=ALL --security-opt=no-new-privileges -p 6667:6667 -p 8080:8080 -v onyx-server:/data onyx-server:latest
#
# The node's sovereign identity key + account store live in /data — mount a
# volume to persist them across restarts. Point the Onyx web client at
# ws://<host>:8080 (build Onyx with VITE_IRC_WS, or use a hosted client).
#
# Only /data needs to be writable. Configuration lives beside the generated
# node key there; a read-only /etc config would prevent first-boot identity
# persistence. Named volumes inherit these initial contents. Bind mounts must
# be provisioned with private configuration/state owned by uid/gid 10001.
FROM alpine:3.20

RUN adduser -D -u 10001 onyx-server \
    && mkdir -p /data \
    && chown onyx-server:onyx-server /data \
    && chmod 0700 /data

# The reproducible artifact produced by packaging/release.sh.
COPY dist/onyx-server-*-x86_64-linux-musl /usr/local/bin/onyx-server
COPY --chown=10001:10001 packaging/onyx-server.quickstart.toml /data/onyx-server.toml
RUN chmod 0600 /data/onyx-server.toml

USER 10001:10001
WORKDIR /data

# 6667 = plaintext IRC · 8080 = browser WebSocket (Onyx). Add TLS (6697/wss) via
# a production config with real certs.
EXPOSE 6667 8080

ENTRYPOINT ["/usr/local/bin/onyx-server"]
CMD ["/data/onyx-server.toml"]
