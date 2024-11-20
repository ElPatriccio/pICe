CC = gcc
CFLAGS = -g -Wall -Wextra

targets = build/pice

all: $(targets)

build/%: build/%.o
	$(CC) -o $@ $<

build/%.o: src/%.c include/common.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	mkdir -p build
	rm -rf build/
	mkdir -p build

