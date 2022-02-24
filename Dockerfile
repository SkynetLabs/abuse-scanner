FROM golang:1.17.7 as builder
LABEL maintainer="SkynetLabs <devs@skynetlabs.com>"

WORKDIR /root

COPY database database
COPY email email
COPY go.mod go.sum main.go Makefile ./

RUN go mod download && make release

FROM golang:1.17.7-alpine
LABEL maintainer="SkynetLabs <devs@skynetlabs.com>"

COPY --from=builder /go/bin/abuse-scanner /go/bin/abuse-scanner

ENTRYPOINT ["abuse-scanner"]
