# Master Makefile for C Fallback Modules
# Builds all pure C implementations

SUBDIRS = dns_scanner network_scanner whois_lookup file_analyzer breach_checker osint_tools

.PHONY: all clean test install $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "Building $@..."
	$(MAKE) -C $@

clean:
	@for dir in $(SUBDIRS); do \
		echo "Cleaning $$dir..."; \
		$(MAKE) -C $$dir clean; \
	done

test:
	@echo "=== Testing all modules ==="
	@for dir in $(SUBDIRS); do \
		echo "\n--- Testing $$dir ---"; \
		$(MAKE) -C $$dir test || true; \
	done

install:
	@for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir install; \
	done

# Individual module targets
dns: 
	$(MAKE) -C dns_scanner

network:
	$(MAKE) -C network_scanner

whois:
	$(MAKE) -C whois_lookup

file:
	$(MAKE) -C file_analyzer

breach:
	$(MAKE) -C breach_checker

osint:
	$(MAKE) -C osint_tools

# Help
help:
	@echo "C Fallback Modules - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build all modules"
	@echo "  clean    - Clean all modules"
	@echo "  test     - Test all modules"
	@echo "  install  - Install all modules"
	@echo ""
	@echo "Individual modules:"
	@echo "  dns      - DNS Scanner"
	@echo "  network  - Port Scanner & Banner Grabber"
	@echo "  whois    - WHOIS Lookup"
	@echo "  file     - File Hash & Analyzer"
	@echo "  breach   - Breach Hash Checker"
	@echo "  osint    - Secret Scanner & Search Engine"
