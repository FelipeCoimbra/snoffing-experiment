CC=gcc
CFLAGS=-I../include
LIBS=-lpcap

SNIFFING_DEPS=../include/sniffing.h ../include/packet.h
SNIFFING_OBJ=sniffing.o
SNIFFING_SRC=sniffing.c
SNIFFING_MAIN=main_sniffing.c

SPOOFING_DEPS=../include/spoofing.h
SPOOFING_OBJ=spoofing.o spoofing_test.o

OBJ=$(SNIFFING_OBJ) $(SPOOFING_OBJ)

$(SNIFFING_OBJ): $(SNIFFING_SRC) $(SNIFFING_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sniffing: $(SNIFFING_OBJ) $(SNIFFING_DEPS) $(SNIFFING_MAIN)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

all: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~
	rm -f sniffing