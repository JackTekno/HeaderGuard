# Tahap build
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY internal/ ./internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/headerguard .

# Tahap runtime — distroless/static (bukan scratch): menyertakan CA certs
# yang dibutuhkan untuk koneksi TLS/DoH keluar.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/headerguard /headerguard
EXPOSE 8080
ENTRYPOINT ["/headerguard"]
# 0.0.0.0 agar port mapping Docker berfungsi (default binary lokal tetap 127.0.0.1)
CMD ["serve", "--addr", "0.0.0.0:8080"]
