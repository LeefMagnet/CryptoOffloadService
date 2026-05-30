# 各语言 Demo 说明

运行前请先启动服务：

```bash
cargo run -p crypto-offload-server -- --listen 127.0.0.1:50051
```

## Go

```bash
make proto
cd sdk/go && go mod tidy
go run ../../examples/go/demo
```

## Python

```bash
make proto
pip install -e sdk/python cryptography
PYTHONPATH=sdk/python python examples/python/demo.py
```

## Rust

```bash
cargo run --example demo --manifest-path examples/rust/Cargo.toml
```

## Java

```bash
cd sdk/java && mvn compile
# 将 examples/java 加入 classpath 后运行 Demo
```

完整 API 说明见 [docs/API.md](../docs/API.md)。
