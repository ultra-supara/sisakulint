ARG GOLANG_VER=1.21.4
ARG ALPINE_VER=latest

FROM golang:${GOLANG_VER} as builder
WORKDIR /go/src/app
COPY go.* *.go ./
COPY cmd cmd/
COPY src src/
ENV CGO_ENABLED 0
ARG SISAKULINT_VER=0.0.3
RUN go mod download
RUN go build -v -ldflags "-s -w -X github.com/ultra-supara/sisakulint/cmd/sisakulint.version=${SISAKULINT_VER}" ./cmd/sisakulint


FROM alpine:${ALPINE_VER}
# bash のインストール
RUN apk add --no-cache bash
# sisaku ユーザーの追加
RUN adduser -D sisaku
# アプリケーションのコピー
COPY --from=builder /go/src/app/sisakulint /usr/local/bin/

# ユーザーの切り替え
USER sisaku
# エントリポイントの設定
ENTRYPOINT ["/usr/local/bin/sisakulint"]
