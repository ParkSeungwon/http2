#include<catch.hpp>
#include<cryptlib.h>
#include<aes.h>
#include<ccm.h>
#include<string>
#include"tls/crypt.h"
#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;
using namespace std;

TEST_CASE("crypto++") {
	
	unsigned char key[16];
	mpz2bnd(random_prime(16), key, key + 16);

	unsigned char iv[16];
	mpz2bnd(random_prime(16), iv, iv + 16);

	string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	CBC_Mode< AES >::Encryption e;
	e.SetKeyWithIV(key, sizeof(key), iv);

	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
				) // StreamTransformationFilter
			); // StringSource
	cout << hexprint("key", key) << endl;
	cout << hexprint("iv", iv) << endl;
	cout << hexprint("cipher", cipher) << endl;

	CBC_Mode< AES >::Decryption d;
	d.SetKeyWithIV(key, sizeof(key), iv);

	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource s1(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
				) // StreamTransformationFilter
			); // StringSource

	cout << recovered << endl;
}


#include <modes.h>

TEST_CASE("crypto") {

    //Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-   
    //bit). This key is secretly exchanged between two parties before communication   
    //begins. DEFAULT_KEYLENGTH= 16 bytes
    unsigned char key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //
    // String and Sink setup
    //
    std::string plaintext = "Now is the time for all good men to come to the aide...";
    std::string ciphertext;
    std::string decryptedtext;

    //
    // Dump Plain Text
    //
    std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
    std::cout << plaintext;
    std::cout << std::endl << std::endl;

    //
    // Create Cipher Text
    //
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ), plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    //
    // Dump Cipher Text
    //
    std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;

    for( int i = 0; i < ciphertext.size(); i++ ) {

        std::cout << "0x" << std::hex << (0xFF & static_cast<uint8_t>(ciphertext[i])) << " ";
    }

    std::cout << std::endl << std::endl;

    //
    // Decrypt
    //
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ), ciphertext.size() );
    stfDecryptor.MessageEnd();

    //
    // Dump Decrypted Text
    //
    std::cout << "Decrypted Text: " << std::endl;
    std::cout << decryptedtext;
    std::cout << std::endl << std::endl;
}
