CC=gcc
CFLAGS=-I../include
LIBS=-lpcap

SNIFFING_DEPS=../include/sniffing.h ../include/packet.h
SNIFFING_OBJ=sniffing.o
SNIFFING_SRC=sniffing.c
SNIFFING_MAIN=main_sniffing.c

SPOOFING_DEPS=../include/spoofing.h
SPOOFING_OBJ=spoofing.o
SPOOFING_SRC=spoofing.c
SPOOFING_MAIN=main_spoofing.c

OBJ=$(SNIFFING_OBJ) $(SPOOFING_OBJ)
DEPS=$(SNIFFING_DEPS) $(SPOOFING_DEPS)

$(SNIFFING_OBJ): $(SNIFFING_SRC) $(SNIFFING_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sniffing: $(SNIFFING_OBJ) $(SNIFFING_DEPS) $(SNIFFING_MAIN)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

$(SPOOFING_OBJ): $(SPOOFING_SRC) $(SPOOFING_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

spoofing: $(SPOOFING_OBJ) $(SPOOFING_DEPS) $(SPOOFING_MAIN)
	$(CC) -o $@ $^ $(CFLAGS)

all: $(OBJ) $(DEPS)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~
	rm -f sniffing spoofing