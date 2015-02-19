// LinkSample.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <Windows.h>    // needed by CHILKAT e.g. for SystemTime

// added for CHILKAT
#include "..\include\ckimap.h" 
//#include "..\include\tchar.h"
//
// need this for various things
extern "C" {
#include "../include/allC.h"
#include "../include/allUnicodeC.h"
}
#include "../include/allUnicode.h"

// for the AES Encryption & Hashing
#include "../include/CkCrypt2.h"


#include "../include/CkRsa.h"
#include "../include/CkPrivateKey.h"
#include "../include/CkPublicKey.h"

// get strings, because the const char* causes problems....
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
const char* message = "This is the test message";


//Function to pause your program - for debugging purposes. Could also use this command [ system("pause"); ]
void key_press(void);

const char * prepared;


void DoNothing(void)
{
	CkImap imap;
	imap.UnlockComponent("T12302015IMAPMAILQ_gdXOQ92bIRDN");
	imap.Connect("imap.gmail.com");

	CkFtp2W ftp2W;

	bool success = ftp2W.UnlockComponent(L"T12302015FTP_yJTfpTRHIR5l");

	HCkSFtpW c_sftp = CkSFtpW_Create();
	int isuccess = CkSFtpW_UnlockComponent(c_sftp, L"T12302015FTP_yJTfpTRHIR5l");
	CkSFtpW_Dispose(c_sftp);

	HCkImap c_imap = CkImap_Create();
	isuccess = CkImap_UnlockComponent(c_imap, "T12302015IMAPMAILQ_gdXOQ92bIRDN");
	CkImap_Dispose(c_imap);
}

void key_press(void)
{
	cout << "\nPress Any Key to Continue!\n\n";
	do {} while (!getchar());
}

void AES(void){
	CkCrypt2 crypt;
	bool success = crypt.UnlockComponent("T12302015Crypt_sHyDCAFglR1v");
	if (success != true) {
		printf("%s\n", crypt.lastErrorText());
		return;
	}

	//  AES is also known as Rijndael.
	crypt.put_CryptAlgorithm("aes");

	//  CipherMode may be "ecb" or "cbc"
	crypt.put_CipherMode("cbc");

	//  KeyLength may be 128, 192, 256
	crypt.put_KeyLength(256);

	crypt.put_EncodingMode("hex");

	//  An initialization vector is required if using CBC mode.
	//  ECB mode does not use an IV.
	//  The length of the IV is equal to the algorithm's block size.
	//  It is NOT equal to the length of the key.
	const char * ivHex;
	ivHex = "000102030405060708090A0B0C0D0E0F";
	crypt.SetEncodedIV(ivHex, "hex");

	//  The secret key must equal the size of the key.  For
	//  256-bit encryption, the binary secret key is 32 bytes.
	//  For 128-bit encryption, the binary secret key is 16 bytes.
	const char * keyHex;
	keyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
	crypt.SetEncodedKey(keyHex, "hex");

	//  Encrypt a string...
	//  The input string is 44 ANSI characters (i.e. 44 bytes), so
	//  the output should be 48 bytes (a multiple of 16).
	//  Because the output is a hex string, it should
	//  be 96 characters long (2 chars per byte).
	const char * encStr;
	printf("%s,\n", message);
	encStr = crypt.encryptStringENC(message);
	printf("Encrypted: %s\n", encStr);

	//  Now decrypt:
	const char * decStr;
	decStr = crypt.decryptStringENC(encStr);
	printf("Decrypted: %s\n\n", decStr);
	Sleep(1000);
}

const char *  SHA1(const char* msg){

	//msg;
	CkCrypt2 sha;
	bool success;
	success = sha.UnlockComponent("T12302015Crypt_sHyDCAFglR1v");
	if (success != true) {
		printf("Crypt component unlock failed\n");
	}

	printf("String to hash with SHA: %s\n", msg);

	sha.put_HashAlgorithm("sha1");
	sha.put_EncodingMode("hex");

	//  Other possible EncodingMode settings are:
	//  "quoted-printable", "base64", and "url"

	const char * hash;
	hash = sha.hashStringENC(msg);
	printf("SHA1:\t %s\n\n", hash);

	return hash;
}

bool generatedKeys = false;
void RSA(const char * hash){
	CkRsa rsa;
	//const char* firsthash = hash;
	bool success;
	success = rsa.UnlockComponent("T12302015RSA_nn56BzHGIRMg");
	if (success != true) {
		printf("RSA component unlock failed\n");
		return;
	}
	const char * publicKey;
	const char * privateKey;

	//  Generate a 1024-bit key.  Chilkat RSA supports
	//  key sizes ranging from 512 bits to 4096 bits.
	if (!generatedKeys){
		success = rsa.GenerateKey(1024);
		if (success != true) {
			printf("%s\n", rsa.lastErrorText());
			return;
		}

		//  Keys are exported in XML format:

		publicKey = rsa.exportPublicKey();

		privateKey = rsa.exportPrivateKey();
		generatedKeys = true;
	}
	printf("Message to encrypt with  RSA: %s\n", message);
	printf("Hashed Message: %c\n", hash);

	CkRsa rsaEncryptor;

	//  Encrypted output is always binary.  In this case, we want
	//  to encode the encrypted bytes in a printable string.
	//  Our choices are "hex", "base64", "url", "quoted-printable".
	rsaEncryptor.put_EncodingMode("hex");

	//  We'll encrypt with the public key and decrypt with the private
	//  key.  It's also possible to do the reverse.
	rsaEncryptor.ImportPublicKey(publicKey);

	bool usePrivateKey;
	usePrivateKey = false;
	const char * encryptedMessage;
	encryptedMessage = rsaEncryptor.encryptStringENC(message, usePrivateKey);
	printf("Encrypted: %s\n\n\n", encryptedMessage);

	//  Now decrypt:
	CkRsa rsaDecryptor;

	rsaDecryptor.put_EncodingMode("hex");
	rsaDecryptor.ImportPrivateKey(privateKey);

	usePrivateKey = true;
	const char * decryptedMessage;
	decryptedMessage = rsaDecryptor.decryptStringENC(encryptedMessage, usePrivateKey);
	const char* newhash = SHA1(decryptedMessage);


	Sleep(5000);
}



int _tmain(int argc, _TCHAR* argv[])
{

	AES();
	RSA(SHA1(message));
	Sleep(20000);
}