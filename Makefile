.PHONY: proto proto-java build-server build-rust-sdk test benchmark docker-test

proto:
	buf generate

# Java stub（mvn protobuf 插件）；Go 用 make proto
proto-java:
	cd sdk/java && mvn compile -q

build-server:
	cargo build --release -p crypto-offload-server

build-rust-sdk:
	cargo build -p cryptooffload-sdk

test:
	cargo test -p crypto-offload-server -- --nocapture

benchmark:
	cargo build --release -p crypto-offload-server --bin crypto-offload-benchmark
	./target/release/crypto-offload-benchmark --mode sign --clients 8 --total-requests 10000

docker-test:
	bash scripts/test/docker_test.sh

run-server:
	cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051

docker-build:
	docker build -f deploy/Dockerfile -t crypto-offload-server:latest .

docker-up:
	docker compose -f deploy/docker-compose.yml up --build -d
