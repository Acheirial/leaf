.PHONY: build test doc proto-gen

build:
	cargo build -p leaf --release

test:
	cargo test -p leaf -- --nocapture

doc:
	cargo doc -p leaf --no-deps

proto-gen:
	./scripts/regenerate_proto_files.sh
