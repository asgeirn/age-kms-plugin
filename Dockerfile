FROM --platform=$BUILDPLATFORM golang AS builder
WORKDIR /usr/src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build

FROM cgr.dev/chainguard/glibc-dynamic
COPY --from=builder /usr/src/age-kms-plugin /usr/bin
USER root
CMD ["/usr/bin/age-kms-plugin"]
