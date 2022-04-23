FROM golang:alpine

MAINTAINER "Maxtune <max@xox.im>"
WORKDIR /build
COPY . .
ENV GO111MODULE=on\
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GOPROXY=https://goproxy.cn
RUN go build -o app .
WORKDIR /dist
RUN cp /build/app .
EXPOSE 14514
ENTRYPOINT ["/dist/app"]