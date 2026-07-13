# Build stage
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/blakhound/blakhound/internal/version.Version=${VERSION}" \
    -o /out/blakhound ./cmd/blakhound

# Runtime stage (distroless, non-root). For development/release testing only;
# BlakHound is a self-contained local binary and does not require Docker.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/blakhound /usr/local/bin/blakhound
USER nonroot
ENTRYPOINT ["/usr/local/bin/blakhound"]
CMD ["--help"]
