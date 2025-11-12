CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS	:= $(CFLAGS) -O0
CFLAGS  := $(CFLAGS) -masm=intel -Wall -Wno-pointer-arith -Wno-int-conversion -Wno-incompatible-pointer-types -w

dawsonloader: clean dist/DawsonLoader.o
	x86_64-w64-mingw32-objcopy --remove-section .bss --strip-debug dist/DawsonLoader.o dist/DawsonLoader.x64.o

dist/DawsonLoader.o: src/DawsonLoader.c
	$(CC_x64) $(CFLAGS) -c src/DawsonLoader.c -o dist/DawsonLoader.o

clean:
	rm -f dist/*.o
	rm -f ./*.c
