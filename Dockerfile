# Dependencies are vendored, so the build needs no network access. The build
# stage runs on the builder's own platform and cross-compiles, so a
# multi-arch build (.github/workflows/release.yml) needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
# Releases pass the tag (.github/workflows/release.yml). A plain build takes
# the version of the newest schema migration, db/migrations/vX.Y.Z.sql, so
# there's no version to bump here.
ARG VERSION
ARG TARGETARCH
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
# Releases also pass the release signing key as a build secret
# (docs/agent.md §5.2). The agent binaries are signed here, so the
# signatures cover exactly the bytes in the image, and the server ships them
# as they are. Without the secret (a local build) the agents are unsigned,
# and agents refuse to update to them.
RUN --mount=type=secret,id=release_signing_key \
    VERSION="${VERSION:-v$(ls db/migrations | sed -n 's/^v\([0-9]*\.[0-9]*\.[0-9]*\)\.sql$/\1/p' | sort -V | tail -n 1)}" \
 && echo "Building Baseline $VERSION" \
 && GOARCH=$TARGETARCH go build -mod=vendor -trimpath -ldflags "-s -w -X main.Version=$VERSION" \
      -o /out/baseline-server ./cmd/baseline-server \
 && for arch in amd64 arm64; do \
      GOOS=linux GOARCH=$arch go build -mod=vendor -trimpath -ldflags "-s -w -X main.Version=$VERSION" \
        -o /out/agent/baseline-agent-linux-$arch ./cmd/baseline-agent; \
    done \
 && if [ -s /run/secrets/release_signing_key ]; then \
      go run -mod=vendor ./cmd/baseline-sign -key /run/secrets/release_signing_key -version "$VERSION" /out/agent/baseline-agent-linux-*; \
    else \
      echo "No release signing key: the agent binaries are unsigned"; \
    fi \
 && mkdir /out/data

# The cluster agent (baseline-agent --mode=k8s, deploy/k8s/baseline-agent.yaml):
#   docker build --target agent -t baseline-agent .
# It runs as nonroot (65532) and keeps its key and certificates in
# /var/lib/baseline, which should be a volume. No BASELINE_STATE_DIR here:
# a deployment from before the rename to Baseline sets JCMDB_STATE_DIR
# and mounts its volume at /var/lib/jcmdb, and that must win.
FROM gcr.io/distroless/static:nonroot AS agent
ARG TARGETARCH
COPY --from=build /out/agent/baseline-agent-linux-${TARGETARCH} /baseline-agent
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/baseline
USER nonroot
ENTRYPOINT ["/baseline-agent", "--mode=k8s"]

# The server. It stays the last stage, so a plain `docker build` builds it.
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=build /out/baseline-server /app/baseline-server
COPY --from=build /out/agent /app/agent
COPY db /app/db
# A named volume mounted here starts with this directory's owner.
COPY --from=build --chown=nonroot:nonroot /out/data /data
ENV BASELINE_DB_SCHEMA=/app/db/db.sql \
    BASELINE_DB_MIGRATIONS=/app/db/migrations \
    BASELINE_AGENT_DIR=/app/agent \
    BASELINE_DATA_DIR=/data
EXPOSE 8080 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["/app/baseline-server", "healthcheck"]
ENTRYPOINT ["/app/baseline-server"]
CMD ["serve"]
