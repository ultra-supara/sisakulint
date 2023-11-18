ARG GOLANG_VER=latest
ARG ALPINE_VER=latest

FROM golang:${GOLANG_VER} as builder
WORKDIR /go/src/app
COPY go.* *.go ./
COPY cmd cmd/
ENV CGO_ENABLED 0
ARG SISAKULINT_VER=0.0.1
RUN go build -v -ldflags "-s -w -X github.com/ultra-supara/cmd/sisakulint.version=${SISAKULINT_VER}" ./cmd/sisakulint

FROM koalaman/shellcheck-alpine:stable as shellcheck

FROM alpine:${ALPINE_VER}
COPY --from=builder /go/src/app/sisakulint /usr/local/bin/
COPY --from=shellcheck /bin/shellcheck /usr/local/bin/shellcheck
USER sisaku
ENTRYPOINT ["/usr/local/bin/sisakulint"]
