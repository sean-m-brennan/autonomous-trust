CC ?= gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

mock_ocsp: mock_ocsp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f mock_ocsp

.PHONY: clean
