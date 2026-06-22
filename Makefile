# sml-x509 build
#
#   make            build the test binary with MLton (default)
#   make test       build + run tests under MLton
#   make test-poly  run tests under Poly/ML (use-and-run; no link step)
#   make all-tests  run the suite under both compilers
#   make example    build + run the demo (parse a real cert chain, verify it)
#   make clean      remove build artifacts
#
# Layout B (dependent): own sources live in src/; the dependency trees are
# vendored under lib/ and loaded in dependency order. The diamonds (BigInt via
# sml-asn1, the SHA codec via sml-pem) are each pulled in along a single path
# (see src/x509.mlb, which includes only sml-rsa); the Poly/ML use-chain below
# mirrors that ordering by hand.

MLTON      ?= mlton
POLY       ?= poly
BIN        := bin

BIGINTDIR  := lib/github.com/sjqtentacles/sml-bigint
CODECDIR   := lib/github.com/sjqtentacles/sml-codec
ASN1DIR    := lib/github.com/sjqtentacles/sml-asn1
PEMDIR     := lib/github.com/sjqtentacles/sml-pem
RSADIR     := lib/github.com/sjqtentacles/sml-rsa

TEST_MLB   := test/test.mlb
SRCS       := $(wildcard $(BIGINTDIR)/* $(CODECDIR)/* $(ASN1DIR)/* $(PEMDIR)/* \
                         $(RSADIR)/* src/* test/*.sml) $(TEST_MLB)

.PHONY: all test poly test-poly all-tests example clean

all: $(BIN)/test-mlton

example: $(BIN)/demo
	./$(BIN)/demo

$(BIN)/demo: $(SRCS) examples/demo.sml examples/sources.mlb | $(BIN)
	$(MLTON) -output $@ examples/sources.mlb

$(BIN)/test-mlton: $(SRCS) | $(BIN)
	$(MLTON) -output $@ $(TEST_MLB)

test: $(BIN)/test-mlton
	$(BIN)/test-mlton

# Poly/ML has no native .mlb support; load each vendored source in dependency
# order (bigint; codec; asn1; pem; rsa), then the x509 sources, then the test
# driver. The suite exits on its own.
poly test-poly:
	printf 'use "$(BIGINTDIR)/bigint.sig";\nuse "$(BIGINTDIR)/bigint.sml";\nuse "$(CODECDIR)/base16.sig";\nuse "$(CODECDIR)/base16.sml";\nuse "$(CODECDIR)/base64.sig";\nuse "$(CODECDIR)/base64.sml";\nuse "$(CODECDIR)/crc32.sig";\nuse "$(CODECDIR)/crc32.sml";\nuse "$(CODECDIR)/sha1.sig";\nuse "$(CODECDIR)/sha1.sml";\nuse "$(CODECDIR)/sha256.sig";\nuse "$(CODECDIR)/sha256.sml";\nuse "$(CODECDIR)/sha512.sig";\nuse "$(CODECDIR)/sha512.sml";\nuse "$(ASN1DIR)/asn1.sig";\nuse "$(ASN1DIR)/asn1.sml";\nuse "$(PEMDIR)/pem.sig";\nuse "$(PEMDIR)/pem.sml";\nuse "$(RSADIR)/rsa.sig";\nuse "$(RSADIR)/rsa.sml";\nuse "src/x509.sig";\nuse "src/x509.sml";\nuse "test/harness.sml";\nuse "test/fixtures.sml";\nuse "test/test_x509.sml";\nuse "test/entry.sml";\nuse "test/main.sml";\n' | $(POLY) -q --error-exit

all-tests: test test-poly

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -f $(BIN)/test-mlton $(BIN)/demo
