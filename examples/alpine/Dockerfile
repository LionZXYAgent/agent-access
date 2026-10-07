# Alpine image running `aac listen --headless --telegram` with the Bitwarden CLI.
#
# Build from the repository root:
#   docker build -f examples/alpine/Dockerfile -t aac-listen .
# Without the Bitwarden CLI (e.g. other providers), ~29 MB instead of ~200 MB:
#   docker build -f examples/alpine/Dockerfile --build-arg WITH_BW=0 -t aac-listen-slim .

FROM rust:1.93-alpine AS build
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf perl make
WORKDIR /src
COPY . .
# Link OpenSSL statically: the resulting binary only depends on musl libc.
ENV OPENSSL_STATIC=1
RUN cargo build --release -p ap-cli && strip target/release/aac

FROM alpine:3.22
ARG WITH_BW=1
RUN apk add --no-cache ca-certificates tini \
 && if [ "$WITH_BW" = "1" ]; then \
      apk add --no-cache nodejs npm && npm install -g @bitwarden/cli && npm cache clean --force; \
    fi \
 && adduser -D -h /var/lib/aac aac
COPY --from=build /src/target/release/aac /usr/local/bin/aac
COPY examples/alpine/entrypoint.sh /usr/local/bin/aac-entrypoint
USER aac
ENV HOME=/var/lib/aac
# Holds the identity key, paired connections, reusable PSK and Bitwarden CLI login state.
VOLUME /var/lib/aac
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/aac-entrypoint"]
CMD ["--reusable-psk", "--token-file", "/var/lib/aac/psk-token"]
