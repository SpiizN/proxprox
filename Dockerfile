FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /proxprox .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openvpn
COPY --from=build /proxprox /usr/local/bin/proxprox
ENTRYPOINT ["/usr/local/bin/proxprox"]
