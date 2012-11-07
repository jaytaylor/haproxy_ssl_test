/*
 * SSL/TLS transport layer over SOCK_STREAM sockets
 *
 * Copyright (C) 2012 EXCELIANCE, Emeric Brun <ebrun@exceliance.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Acknowledgement:
 *   We'd like to specially thank the Stud project authors for a very clean
 *   and well documented code which helped us understand how the OpenSSL API
 *   ought to be used in non-blocking mode. This is one difficult part which
 *   is not easy to get from the OpenSSL doc, and reading the Stud code made
 *   it much more obvious than the examples in the OpenSSL package. Keep up
 *   the good works, guys !
 *
 *   Stud is an extremely efficient and scalable SSL/TLS proxy which combines
 *   particularly well with haproxy. For more info about this project, visit :
 *       https://github.com/bumptech/stud
 *
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <ebmbtree.h>

struct sni_ctx {
	SSL_CTX *ctx;             /* context associated to the certificate */
	int order;                /* load order for the certificate */
	struct ebmb_node name;    /* node holding the servername value */
};

static int ssl_sock_load_cert_file(const char *path) {
	SSL_library_init();
	int ret;
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx) {
		unsigned long code = ERR_get_error();
		printf("error code: %i\n", code);
		printf("unable to allocate SSL context for cert '%s'.\n", path);
		printf("Fn: %s\n", ERR_func_error_string(code));
		printf("Error: %s\n", ERR_reason_error_string(code));
		ERR_print_errors_fp(stdout);
		return 1;
	}

	int jtest = SSL_CTX_use_PrivateKey_file(ctx, path, SSL_FILETYPE_PEM);
	if (jtest <= 0) {
		printf("FAILED, the result of SSL_CTX_use_PrivateKey_file retval was '%i'\n", jtest);
		printf("path='%s'\n", path);
		printf("unable to load SSL private key from PEM file '%s'.\n", path);
		SSL_CTX_free(ctx);
		return 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	if (argc == 1) {
		printf("error: need PEM filename argument");
		return 1;
	}
	int result = ssl_sock_load_cert_file(argv[1]);
	if (result == 0) {
		printf("Success! The PEM file was successfully loaded\n");
	}
	return result;
}
