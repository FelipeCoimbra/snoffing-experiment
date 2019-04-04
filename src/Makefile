CC=gcc
CFLAGS=-I../include
LIBS=-lpcap

SNIFFTEST_DEPS=../include/sniffing.h
SNIFFTEST_OBJ=sniffing.o
SNIFFTEST_SRC=sniffing.c
SNIFFTEST_MAIN=main_sniffing.c

SPOOFTEST_DEPS=../include/spoofing.h
SPOOFTEST_OBJ=spoofing.o spoofing_test.o

OBJ=$(SNIFFTEST_OBJ) $(SPOOFTEST_OBJ)

$(SNIFFTEST_OBJ): $(SNIFFTEST_SRC) $(SNIFFTEST_DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sniffing: $(SNIFFTEST_OBJ) $(SNIFFTEST_DEPS) $(SNIFFTEST_MAIN)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

all: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f *.o *~
	rm -f sniffing