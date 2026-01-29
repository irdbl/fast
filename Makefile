PREFIX ?= /usr/local
BINARY = fast

.PHONY: all build release install uninstall clean

all: release

build:
	cargo build

release:
	cargo build --release

install: release
	install -d $(PREFIX)/bin
	install -m 755 target/release/$(BINARY) $(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)

clean:
	cargo clean
