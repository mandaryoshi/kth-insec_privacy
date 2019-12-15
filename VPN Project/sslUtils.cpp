//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>

BIO *bio_err = 0;
unsigned char key[32];								//global key and initialization vector variables used for data transfer channel
unsigned char iv[16];

int berr_exit(const char *string) {
	BIO_printf(bio_err, "%s\n", string);
	ERR_print_errors(bio_err);
	exit(0);
}

//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
	/* In this function, you handle
	 * 1) The SSL handshake between the server and the client.
	 * 2) Authentication
	 * 		a) Both the server and the client rejects if the presented certificate is not signed by the trusted CA.
	 * 		b) Client rejects if the the server's certificate does not contain a pre-defined string of your choice in the common name (CN) in the subject.
	 */
	BIO *bio;
	BIO *outbio;
	SSL *ssl;
	SSL_CTX *ctx;
	X509 *cert;
	X509_NAME *certname;

	SSL_library_init();
	SSL_load_error_strings();
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	if (role == 0)
		ctx = SSL_CTX_new(SSLv23_server_method());		//creating a new context
	else
		ctx = SSL_CTX_new(SSLv23_client_method());

	if (SSL_CTX_load_verify_locations(ctx,NULL,rootCApath) != 1){			//to make rootCApath work we had to use c_rehash in the terminal
				printf("Couldn't load CA.\n");
				SSL_CTX_free(ctx);
		}


	// Loading up certificates and keys
	if (SSL_CTX_use_certificate_file(ctx,certfile,SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM) <= 0){
		ERR_print_errors_fp(stderr);
	}
	if (SSL_CTX_check_private_key(ctx) != 1){
		ERR_print_errors_fp(stderr);
	}

	//setting verification flags to be mode
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	//creating a new SSL structure for connection
	ssl = SSL_new(ctx);

	//BIO is used to hide I/O details from the application
	bio = BIO_new_socket(contChannel,BIO_NOCLOSE);
	SSL_set_bio(ssl, bio, bio);
	BIO_get_ssl(bio, &ssl);

	if (role == 0){
			SSL_accept(ssl);		//Server should accept the connection request from the client
	}
		else {
			SSL_connect(ssl);		//Client should connect to the server
	}

	printf("SSL connection using %s\n", SSL_get_cipher (ssl));		//For debugging purposes, shows the type of connection

	if (role == 0 ) {												//If server, then verify common name
		cert = SSL_get_peer_certificate(ssl);
		printf("Client certificate:\n");

		certname = X509_NAME_new();
		certname = X509_get_subject_name(cert);

		//Showing the subject and the issuer of the certificates, for debugging purposes mostly
		char* subject;
		subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", subject);
		char* issuer;
		issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer : %s\n", issuer);

		/* SPLITTING FUNCTION */
		int j = 0;
		char * pch2;
		char * commonname2;
		printf ("Splitting string \"%s\" into tokens:\n",issuer);
		pch2 = strtok (issuer,"/");
		while (pch2 != NULL)
		{
			printf ("%s\n",pch2);					//printing each of the certificate fields for debugging
			pch2 = strtok (NULL, "/");				//splitting the certificate information and getting the CNs out the direct way
			j++;
			if (j == 5)								//CN is 5th in the list of the certificate information
				commonname2 = pch2;
		}
		printf("Commonname2 is %s\n", commonname2);

		// comparing if the issuer is correct
		char * correct = "CAs match found";
		char * wrong = "CAs do not match. Exiting.";
		if (strcmp("CN=TP CA asratyan@kth.se mandarj@kth.se", commonname2) == 0)
			printf("Proceeding, %s\n", correct);		//Proceed if CAs match
		else {
			printf("Error: %s \n", wrong);
			BIO_ssl_shutdown(bio);						//Close the connection if the CAs do not match
			}
		X509_free(cert);
	}
	//Clean up


	return ssl;
}

void dataChannelKeyExchange(int role, SSL *ssl) {
	/* In this function, you handle
	 * 1) The generation of the key and the IV that is needed to symmetrically encrypt/decrypt the IP datagrams over UDP (data channel).
	 * 2) The exchange of the symmetric key and the IV over the control channel secured by the SSL object.
	 */

	//Server creates a random number for key and iv and transfers it to the client
	if (role == 0) {
		RAND_bytes(key, sizeof key);
		SSL_write(ssl, key, 32);
	//The size of the key and IV depend on the cipher we are using, in this case it is
	//AES 256 in CBC mode, and for this we need a key of length 256 bits with an IV of 128 bits,
	//hence the size of the key is 32 bytes and 16 bytes for the IV
		RAND_bytes(iv, sizeof iv);
		SSL_write(ssl, iv, 16);

	}
	else {
		//client just needs to read
		SSL_read(ssl, key, 32);
		SSL_read(ssl, iv, 16);
	}

}

int encrypt(unsigned char *plainText, int plainTextLen,
		unsigned char *cipherText) {
	/* In this function, you store the symmetrically encrypted form of the IP datagram at *plainText, into the memory at *cipherText.
	 * The memcpy below directly copies *plainText into *cipherText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */

	/*	Both server and client send each other an "I" for initialization, which can be seen in the TP.cpp at lines 264 and 287.
	 *  Because this message consists of only 1 symbol, it is not a multiple of the block size of the cipher, which means that
	 *  the message will not be processed properly and will result in "Writing to buffer: invalid argument".
	 *  To fix this, we have tried to tinker with (plainTextLen/cipherTextLen modulo block size) != 0 and return 0 in that case.
	 *  However, returning 0 seemed to still give the invalid argument, and we did not know what to return instead.
	 *
	 *  Some of the examples we have tried:
	 *
	 *  if (cipherTextLen ==1) return 0;
	 *  if (((EVP_CIPHER_CTX_block_size(ctx) % cipherTextLen)  != 0) || cipherTextLen ==1) return 0;
	 *
	 *	Encrypted traffic works perfectly fine, apart from the first "I" message.
	 */
	// Create and initialise the context
	EVP_CIPHER_CTX *ctx;
	int len;
	int cipherTextLen;

	ctx = EVP_CIPHER_CTX_new();

	//Initialise the encryption operation
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

	//Provide the message to be encrypted, and get the encrypted output
	EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen);
	cipherTextLen = len;

	//Finalise the encryption so more ciphertext bytes can be written here
	EVP_EncryptFinal_ex(ctx, cipherText + len, &len);

	cipherTextLen += len;
	//memcpy(cipherText, plainText, plainTextLen);

	//Clean up
	EVP_CIPHER_CTX_free(ctx);

	return cipherTextLen;
}

int decrypt(unsigned char *cipherText, int cipherTextLen,
		unsigned char *plainText) {
	/* In this function, you symmetrically decrypt the data at *cipherText and store the output IP datagram at *plainText.
	 * The memcpy below directly copies *cipherText into *plainText, therefore the tunnel works unencrypted. It is there for you to
	 * test if the tunnel works initially, so remove that line once you start implementing this function.
	 */
	//

	EVP_CIPHER_CTX *ctx;
	int len;
	int plainTextLen;

	//This is the exact same sequence of methods as in encrypt, but the only difference is that it uses "Decrypt"
	ctx = EVP_CIPHER_CTX_new();

	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);


	EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen);

	plainTextLen = len;

	EVP_DecryptFinal_ex(ctx, plainText + len, &len);

	plainTextLen += len;

	EVP_CIPHER_CTX_free(ctx);

	return plainTextLen;
}

