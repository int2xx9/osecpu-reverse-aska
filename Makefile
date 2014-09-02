CC=gcc
CFLAGS=
MAKE=make
TARGET=reverse-osecpu-aska
SOURCE=main.c
RM=rm -f

.PHONY: default all clean
default:
	@$(MAKE) --no-print-directory all

all:
	@$(MAKE) --no-print-directory $(TARGET)

clean:
	$(RM) $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) -o $(TARGET) $(CFLAGS) $(SOURCE)

