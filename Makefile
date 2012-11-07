all:
	gcc ssl_test.c -I. -I/usr/include -I/usr/local/include -L/usr/local/lib -L/usr/lib -lssl -lcrypto -o ssl_test

clean:
	rm -f binary
