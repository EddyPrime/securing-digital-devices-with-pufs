
FROM ubuntu:24.04

# Install build and development dependencies.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        clang-format-18 \
        findutils \
        mawk && \
    rm -rf /var/lib/apt/lists/*

# Copy the repository into the container.
WORKDIR /workspace
COPY --chown=10001:10001 . .

# Build both projects as an unprivileged user.
USER 10001:10001
RUN make release WERROR=1

# Display the available commands by default.
CMD ["make", "help"]
