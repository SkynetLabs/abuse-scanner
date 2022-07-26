FROM golang:1.18.3 as builder
LABEL maintainer="SkynetLabs <devs@skynetlabs.com>"

WORKDIR /root

ENV CGO_ENABLED=0

COPY . .

RUN go mod download && make release

FROM alpine:3.16.1
LABEL maintainer="SkynetLabs <devs@skynetlabs.com>"

COPY --from=builder /go/bin/abuse-scanner /usr/bin/abuse-scanner

ENTRYPOINT ["abuse-scanner"]
