ARG GOLANG_VER=latest
ARG ALPINE_VER=latest
ARG TOKEN

FROM golang:${GOLANG_VER} as builder
WORKDIR /go/src/app
COPY go.* *.go ./
COPY cmd cmd/
ENV CGO_ENABLED 0
ARG SISAKULINT_VER=0.0.0
RUN export GOPRIVATE=github.com/ultrasupara/sisakulint
RUN git config --global url."https://x-access-token:${TOKEN}@github.com/".insteadOf "https://github.com/"
RUN go mod download
RUN go build -v -ldflags "-s -w -X github.com/ultra-supara/sisakulint/cmd/sisakulint.version=${SISAKULINT_VER}" ./cmd/sisakulint

FROM koalaman/shellcheck-alpine:stable as shellcheck

FROM alpine:${ALPINE_VER}
COPY --from=builder /go/src/app/sisakulint /usr/local/bin/
COPY --from=shellcheck /bin/shellcheck /usr/local/bin/shellcheck
USER sisaku
ENTRYPOINT ["/usr/local/bin/sisakulint"]
