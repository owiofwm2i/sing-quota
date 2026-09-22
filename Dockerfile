FROM golang:1.25-bookworm AS sing-box-build

ARG SING_BOX_VERSION
RUN test -n "$SING_BOX_VERSION" \
  && git clone --depth 1 --branch "$SING_BOX_VERSION" https://github.com/SagerNet/sing-box.git /src
WORKDIR /src
RUN mkdir -p /out \
  && tags="$(paste -sd, release/DEFAULT_BUILD_TAGS),with_v2ray_api,with_purego" \
  && ldflags="-X github.com/sagernet/sing-box/constant.Version=$SING_BOX_VERSION $(tr '\n' ' ' < release/LDFLAGS)" \
  && CGO_ENABLED=0 go build -trimpath -tags "$tags" -ldflags "$ldflags" \
    -o /out/sing-box ./cmd/sing-box

FROM golang:1.25-bookworm AS grpcurl-build
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.3

FROM debian:bookworm-slim AS sing-box
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=sing-box-build /out/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
CMD ["run", "-c", "/etc/sing-box/config.json"]

FROM python:3.13-slim AS manager
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates tzdata \
  && rm -rf /var/lib/apt/lists/*
COPY --from=sing-box-build /out/sing-box /usr/local/bin/sing-box
COPY --from=grpcurl-build /out/grpcurl /usr/local/bin/grpcurl
COPY quota.py stats.proto /app/
ENTRYPOINT ["python3", "/app/quota.py"]
CMD ["watch"]
