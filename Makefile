NAME := StringReaper
CC_x64 := x86_64-w64-mingw32-gcc

all: 
	x86_64-w64-mingw32-gcc $(NAME).c -O0 -c -o $(NAME).o -masm=intel
clean:
	rm $(BOFNAME).o
