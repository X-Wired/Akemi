# Akemi v2.0.0 multi-stage Docker build

ARG GO_VERSION=1.24
ARG RUST_VERSION=1.85
ARG AKEMI_VERSION=2.0.0

# Stage 1: Rust engines (Akemi-Spear + DotHound)
FROM rust:${RUST_VERSION}-alpine AS rust-builder
RUN apk add --no-cache build-base cmake perl pkgconf musl-dev libpcap-dev

WORKDIR /build
COPY Akemi-Spear/ Akemi-Spear/
COPY DotHound/ DotHound/

RUN cd Akemi-Spear && \
    cargo build --release --locked && \
    ./target/release/Akemi-Spear --version && \
    strip target/release/Akemi-Spear

RUN cd DotHound && \
    cargo build --release --locked && \
    ./target/release/dothound --version && \
    strip target/release/dothound

# Stage 2: Go CLI
FROM golang:${GO_VERSION}-alpine AS go-builder
ARG AKEMI_VERSION
RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.Version=${AKEMI_VERSION}" -o akemi ./cmd/Akemi && \
    ./akemi --version

# Stage 3: Runtime image
FROM alpine:3.20
ARG AKEMI_VERSION

LABEL org.opencontainers.image.title="Akemi"
LABEL org.opencontainers.image.description="Surface Map Attack Framework - attack surface mapping and vulnerability validation"
LABEL org.opencontainers.image.version="${AKEMI_VERSION}"
LABEL org.opencontainers.image.authors="Wired, Fuwa, Vo1d"

RUN apk add --no-cache ca-certificates libgcc libpcap && \
    mkdir -p /etc/akemi/probes /etc/akemi/config /var/lib/akemi /results

COPY --from=go-builder /build/akemi /usr/local/bin/akemi
COPY --from=rust-builder /build/Akemi-Spear/target/release/Akemi-Spear /usr/local/bin/Akemi-Spear
COPY --from=rust-builder /build/DotHound/target/release/dothound /usr/local/bin/dothound

COPY probes/ /etc/akemi/probes/
COPY config/ /etc/akemi/config/
COPY akemi.conf /etc/akemi/akemi.conf

ENV AKEMI_DB_DSN=/var/lib/akemi/akemi.db

EXPOSE 9090

ENTRYPOINT ["akemi"]
CMD ["--help"]
