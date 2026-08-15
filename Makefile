CC      ?= gcc
CFLAGS   = -O2 -Wall -Wextra -Wno-unused-parameter -std=c11
LDFLAGS  = -lsodium -loqs -lmagic -lgd -lexpat

HAVE_SYSTEMD := $(shell pkg-config --exists libsystemd 2>/dev/null && echo 1)
ifeq ($(HAVE_SYSTEMD),1)
CFLAGS  += -DHAVE_SYSTEMD
LDFLAGS += $(shell pkg-config --libs libsystemd)
endif

HAVE_YARA := $(shell pkg-config --exists yara 2>/dev/null && echo 1)
ifeq ($(HAVE_YARA),1)
CFLAGS  += -DHAVE_YARA
LDFLAGS += $(shell pkg-config --libs yara)
endif

HAVE_SECCOMP := $(shell pkg-config --exists libseccomp 2>/dev/null && echo 1)
ifeq ($(HAVE_SECCOMP),1)
CFLAGS  += -DHAVE_SECCOMP
LDFLAGS += $(shell pkg-config --libs libseccomp)
endif

HAVE_ZLIB := $(shell pkg-config --exists zlib 2>/dev/null && echo 1)
ifeq ($(HAVE_ZLIB),1)
CFLAGS  += -DHAVE_ZLIB
LDFLAGS += $(shell pkg-config --libs zlib)
else
$(warning zlib dev headers not found: zip trial-inflate (SEC-UP-02) compiles out, declared sizes go unverified)
endif

SRCS = main.c \
       admission.c \
       crypto.c \
       attestation.c \
       audit.c \
       scanner.c \
       scanner_whitelist.c \
       clamav.c \
       yara.c \
       seccomp.c \
       sanitizers/image.c \
       sanitizers/svg.c \
       sanitizers/text.c \
       sanitizers/archive.c \
       sanitizers/pdf.c \
       sanitizers/video.c \
       sanitizers/audio.c \
       vendor/cjson/cJSON.c

OBJS = $(SRCS:.c=.o)
BIN  = pigcloud-tee-scanner

PYTHON          ?= python3
FILE_TYPES_JSON  = file-types.json
WHITELIST_H      = scanner_whitelist.h
WHITELIST_C      = scanner_whitelist.c
WHITELIST_GEN    = gen_whitelist.py

PREFIX      ?= /usr/local
SYSTEMD_DIR  = /etc/systemd/system
LOGROTATE_DIR = /etc/logrotate.d
SCRIPTS_DIR  = $(PREFIX)/lib/pigcloud-tee

.PHONY: all clean install uninstall test test-e2e e2e-self-check setup-user deploy vector-check admission-test spawn-test image-test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(WHITELIST_H) $(WHITELIST_C) &: $(FILE_TYPES_JSON) $(WHITELIST_GEN)
	$(PYTHON) $(WHITELIST_GEN) $(FILE_TYPES_JSON) $(WHITELIST_H) $(WHITELIST_C)

main.o: main.c protocol.h admission.h crypto.h attestation.h audit.h scanner.h vendor/cjson/cJSON.h
admission.o: admission.c admission.h protocol.h vendor/cjson/cJSON.h
crypto.o: crypto.c crypto.h protocol.h
attestation.o: attestation.c attestation.h
audit.o: audit.c audit.h protocol.h vendor/cjson/cJSON.h
scanner.o: scanner.c scanner.h clamav.h yara.h protocol.h sanitizers/sanitizers.h $(WHITELIST_H)
scanner_whitelist.o: $(WHITELIST_C) $(WHITELIST_H)
clamav.o: clamav.c clamav.h protocol.h
yara.o: yara.c yara.h
seccomp.o: seccomp.c seccomp.h
sanitizers/image.o: sanitizers/image.c sanitizers/sanitizers.h protocol.h $(WHITELIST_H)
sanitizers/svg.o: sanitizers/svg.c sanitizers/sanitizers.h protocol.h
sanitizers/text.o: sanitizers/text.c sanitizers/sanitizers.h protocol.h
sanitizers/archive.o: sanitizers/archive.c sanitizers/sanitizers.h protocol.h $(WHITELIST_H)
sanitizers/pdf.o: sanitizers/pdf.c sanitizers/sanitizers.h protocol.h sanitizers/memfd_helpers.h
sanitizers/video.o: sanitizers/video.c sanitizers/sanitizers.h protocol.h sanitizers/memfd_helpers.h
sanitizers/audio.o: sanitizers/audio.c sanitizers/sanitizers.h protocol.h sanitizers/memfd_helpers.h $(WHITELIST_H)

clean:
	rm -f $(OBJS) $(BIN) $(WHITELIST_H) $(WHITELIST_C) tests/vector_check tests/admission_harness tests/spawn_harden_test tests/image_anim_test

setup-user:
	@if ! id pigcloud-tee >/dev/null 2>&1; then \
		echo "Creating pigcloud-tee system user..."; \
		useradd --system --no-create-home --shell /usr/sbin/nologin \
			--groups www-data pigcloud-tee; \
	else \
		echo "User pigcloud-tee already exists."; \
	fi
	@mkdir -p /tmp/pigcloud-tee
	@chown pigcloud-tee:www-data /tmp/pigcloud-tee
	@chmod 750 /tmp/pigcloud-tee

install: $(BIN)
	install -m 755 $(BIN) $(PREFIX)/bin/
	install -d $(SYSTEMD_DIR)
	install -m 644 systemd/pigcloud-tee-scanner.service $(SYSTEMD_DIR)/
	install -m 644 systemd/pigcloud-tee-scanner.socket $(SYSTEMD_DIR)/
	install -m 644 systemd/pigcloud-tee-signer.service $(SYSTEMD_DIR)/
	install -m 644 systemd/pigcloud-tee-signer.socket $(SYSTEMD_DIR)/
	install -d $(LOGROTATE_DIR)
	install -m 644 deploy/logrotate.conf $(LOGROTATE_DIR)/pigcloud-tee-scanner
	install -d $(SCRIPTS_DIR)
	install -m 755 deploy/health-check.sh $(SCRIPTS_DIR)/
	install -m 755 deploy/monitor-cron.sh $(SCRIPTS_DIR)/
	@if [ -f /usr/share/misc/magic.mgc ]; then \
		install -m 644 /usr/share/misc/magic.mgc $(SCRIPTS_DIR)/magic.mgc; \
		echo "Pinned libmagic DB → $(SCRIPTS_DIR)/magic.mgc"; \
	else \
		echo "NOTE: /usr/share/misc/magic.mgc not found — libmagic default will be used"; \
	fi
	systemctl daemon-reload
	@echo ""
	@echo "Installed. Next steps:"
	@echo "  1. make setup-user  (if first install)"
	@echo "  2. systemctl enable --now pigcloud-tee-scanner.socket pigcloud-tee-scanner"
	@echo "  3. systemctl status pigcloud-tee-scanner"

uninstall:
	systemctl stop pigcloud-tee-scanner.socket pigcloud-tee-scanner 2>/dev/null || true
	systemctl disable pigcloud-tee-scanner.socket pigcloud-tee-scanner 2>/dev/null || true
	rm -f $(PREFIX)/bin/$(BIN)
	rm -f $(SYSTEMD_DIR)/pigcloud-tee-scanner.service
	rm -f $(SYSTEMD_DIR)/pigcloud-tee-scanner.socket
	rm -f $(LOGROTATE_DIR)/pigcloud-tee-scanner
	rm -rf $(SCRIPTS_DIR)
	systemctl daemon-reload

deploy: $(BIN) setup-user install
	systemctl enable pigcloud-tee-scanner
	systemctl restart pigcloud-tee-scanner
	@sleep 1
	@$(SCRIPTS_DIR)/health-check.sh || echo "WARNING: Health check failed after deploy"

test: $(BIN)
	@echo "Starting daemon in background..."
	@rm -f /tmp/pigcloud-tee-test.sock
	./$(BIN) --socket /tmp/pigcloud-tee-test.sock &
	@sleep 0.5
	@echo "Sending health check..."
	@printf '\x00\x00\x00\x0f{"op":"health"}' | socat - UNIX-CONNECT:/tmp/pigcloud-tee-test.sock | tail -c +5
	@echo
	@kill %1 2>/dev/null || true
	@rm -f /tmp/pigcloud-tee-test.sock
	@echo "Smoke test passed."

test-e2e:
	$(PYTHON) tests/e2e_test.py

e2e-self-check:
	$(PYTHON) tests/e2e_test.py --self-check

vector-check: tests/vector_check
	./tests/vector_check ../tests/vectors/chunked_file_v1.json

tests/vector_check: tests/vector_check.c crypto.c crypto.h protocol.h vendor/cjson/cJSON.c vendor/cjson/cJSON.h
	$(CC) $(CFLAGS) -o $@ tests/vector_check.c crypto.c vendor/cjson/cJSON.c -lsodium -loqs

admission-test: tests/admission_harness
	./tests/admission_harness

spawn-test: tests/spawn_harden_test
	./tests/spawn_harden_test

tests/spawn_harden_test: tests/spawn_harden_test.c sanitizers/memfd_helpers.h
	$(CC) -O2 -Wall -Wextra -std=c11 -o $@ tests/spawn_harden_test.c

image-test: tests/image_anim_test
	./tests/image_anim_test

tests/image_anim_test: tests/image_anim_test.c sanitizers/image.c sanitizers/sanitizers.h $(WHITELIST_H) $(WHITELIST_C)
	$(CC) $(CFLAGS) -o $@ tests/image_anim_test.c $(WHITELIST_C) -lgd

tests/admission_harness: tests/admission_harness.c admission.c admission.h protocol.h \
                         deploy/monitor-cron.sh vendor/cjson/cJSON.c vendor/cjson/cJSON.h
	$(CC) -O2 -Wall -Wextra -std=c11 -pthread \
		-DTEE_MONITOR_CRON='"$(CURDIR)/deploy/monitor-cron.sh"' \
		-o $@ tests/admission_harness.c admission.c vendor/cjson/cJSON.c

SGX_SIGN_KEY ?= enclave_signing_key.pem

$(SGX_SIGN_KEY):
	openssl genrsa -3 3072 > $@

manifest.sgx: manifest.template $(BIN)
	gramine-manifest \
		-Darch_libdir=/lib/x86_64-linux-gnu \
		-Dlog_level=warning \
		$< $(@:.sgx=)
	gramine-sgx-sign \
		--manifest $(@:.sgx=) \
		--key $(SGX_SIGN_KEY) \
		--output $@

sgx: manifest.sgx
	@echo "MRENCLAVE:"
	@gramine-sgx-get-token --manifest $< 2>/dev/null | grep mr_enclave || echo "(run on SGX hardware)"
