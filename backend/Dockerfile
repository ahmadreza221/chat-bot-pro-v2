# -------- Build stage --------
FROM rust:1.78 as builder

WORKDIR /app
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release -q
RUN rm -rf src
COPY backend/src ./src
RUN cargo build --release -q

# -------- Runtime stage --------
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/backend ./
ENV RUST_LOG=info
EXPOSE 8080
CMD ["./backend"] 