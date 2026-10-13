nasm -f win32 printA.asm -o printA.o
ld -mi386pe printA.o -o printA.exe