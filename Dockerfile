FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ndr-server ./cmd/server

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/ndr-server /app/ndr-server
EXPOSE 8080
ENV NDR_SERVER_ADDR=:8080
ENTRYPOINT ["/app/ndr-server"]
