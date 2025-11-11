CC_x64 := x86_64-w64-mingw32-gcc
CFLAGS	:= $(CFLAGS) -O0
CFLAGS  := $(CFLAGS) -masm=intel -Wall -Wno-pointer-arith -Wno-int-conversion -Wno-incompatible-pointer-types -w

dawsonloader: clean dist/DawsonLoader.o dist/jopcall_integration.o
	x86_64-w64-mingw32-ld -r dist/DawsonLoader.o dist/jopcall_integration.o -o dist/DawsonLoader.x64.tmp.o
	x86_64-w64-mingw32-objcopy --remove-section .bss --strip-debug dist/DawsonLoader.x64.tmp.o dist/DawsonLoader.x64.o
	rm -f dist/DawsonLoader.x64.tmp.o

dist/DawsonLoader.o: src/DawsonLoader.c
	$(CC_x64) $(CFLAGS) -c src/DawsonLoader.c -o dist/DawsonLoader.o

dist/jopcall_integration.o: src/jopcall_integration.c
	$(CC_x64) $(CFLAGS) -c src/jopcall_integration.c -o dist/jopcall_integration.o

clean:
	rm -f dist/*.o
	rm -f ./*.c
