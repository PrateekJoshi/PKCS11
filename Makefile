all : app

app : main.o

main.o : main.c 
	gcc -I/usr/local/lib main.c -o main.o -ldl -g

clean:
	rm -rf main.o
