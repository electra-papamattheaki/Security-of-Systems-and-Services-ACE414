all: client server

client: client.c 
	gcc -Wall -o client client.c -L/usr/lib -lssl -lcrypto
	
server: server.c
	gcc -Wall -o server server.c -L/usr/lib -lssl -lcrypto
