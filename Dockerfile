FROM rust:1.67-bullseye as builder

WORKDIR /usr/src/ns-ip

COPY . .

RUN cargo build --release

FROM debian:bullseye-slim

COPY --from=builder /usr/src/ns-ip/target/release/ns-ip /usr/local/bin/ns-ip

EXPOSE 53/udp

ENTRYPOINT ["/usr/local/bin/ns-ip"]
