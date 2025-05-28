# Makefile for building trace utility

CC := clang
CFLAGS := -Wall -fPIC

# Check for architecture from environment variable
ifdef ARCHITECTURE
	ifeq ($(ARCHITECTURE),i386)
		CFLAGS += -m32
	endif
endif

# Output files
LIB_NAME := trace
SHARED_LIB := lib$(LIB_NAME).so
STATIC_LIB := lib$(LIB_NAME).a
SRC := trace.c

all: $(SHARED_LIB) $(STATIC_LIB)

# Compile shared library
$(SHARED_LIB): trace.c
	$(CC) $(CFLAGS) -shared -o $@ $< -ldl

# Compile static library
$(STATIC_LIB): trace.c
	$(CC) $(CFLAGS) -c $< -o trace.o
	ar rcs $@ trace.o
	rm -f trace.o

clean:
	rm -f $(SHARED_LIB) $(STATIC_LIB)

.PHONY: all clean