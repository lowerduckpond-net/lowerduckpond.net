# The controller joins the dedicated daemon's host network. No secret enters
# this build context; the launcher sends only this Dockerfile and mise.toml.
FROM ubuntu:26.04@sha256:3595d7fc4286a33fad0fd853a4063e654287a9c3787437d7937c94ca3f7a804e

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        bash ca-certificates coreutils curl docker.io git iproute2 jq \
        openssh-client procps python3 rsync tar unzip util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        https://github.com/jdx/mise/releases/download/v2026.8.8/mise-v2026.8.8-linux-x64 \
        --output /usr/local/bin/mise \
    && printf '%s\n' '1fce52a3656cf14bef6feeb9f0b90d545126a0bb598f0a69afbb9e4702f8f3e3  /usr/local/bin/mise' | sha256sum --check \
    && chmod 0755 /usr/local/bin/mise

ENV MISE_DATA_DIR=/opt/mise-data \
    MISE_CONFIG_DIR=/opt/mise-config \
    MISE_YES=1 \
    MISE_TRUSTED_CONFIG_PATHS=/opt/qualification-tools:/opt/lifecycle:/work/source \
    PATH=/opt/mise-data/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /opt/qualification-tools
COPY mise.toml ./mise.toml
RUN mise install \
    && mise install aqua:1password/cli@2.33.0 \
    && ln -s /opt/mise-data/installs/aqua-1password-cli/2.33.0/op /usr/local/bin/op \
    && mise reshim

WORKDIR /opt/lifecycle
ENTRYPOINT ["/usr/local/bin/mise", "exec", "--"]
