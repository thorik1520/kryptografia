/*
 * main.cpp
 *
 *  Created on: 6 lis 2015
 *      Author: thorik
 */
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "modes.h"

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::StringSource;
using CryptoPP::ArraySource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "aes.h"
using CryptoPP::AES;

#include "eax.h"
using CryptoPP::EAX;

#include "sha.h"
using CryptoPP::SHA256;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

#include <fstream>
using std::ifstream;
using std::ofstream;

#include "conio.h"

void generate_key() {
	string plain_keystore_key = "91945D3F4DCBEE0BF45EF52255F095A4";
	byte iv[ AES::BLOCKSIZE * 16 ] = "000102030405060708090a0b0c0d0e0f";

	int c;
	string key_string;
	cprintf("New keystore password:\n");
	while((c = getch()) != (int)'\n') {
		cprintf("*");
		key_string += (char)c;
	}
	while(key_string.length() != AES::DEFAULT_KEYLENGTH)
		key_string += '0';

	endwin();

	byte key[ AES::DEFAULT_KEYLENGTH ];
	StringSource(key_string, true,
		new ArraySink( key, sizeof(key) )
	); // StringSource

	EAX< AES >::Encryption enc;
	enc.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

	string encrypted_keystore_key;
	StringSource( plain_keystore_key, true,
		new AuthenticatedEncryptionFilter( enc,
				new HexEncoder(
						new StringSink( encrypted_keystore_key ))));

	ofstream enc_file;
	enc_file.open ("keystore");
	enc_file << encrypted_keystore_key;
	enc_file.close();
	//cout << endl << "Copy this to keystore:" << endl << encrypted_keystore_key << endl;
}

void generate_config() {
	string config_key = "91945D3F4DCBEE0BF45EF52255F095A4";
	byte iv[ AES::BLOCKSIZE * 16 ] = "000102030405060708090a0b0c0d0e0f";
	string keystore_key_number = "1";
	string keystore_path = "./keystore";

	SHA256 hash;
	byte digest[ SHA256::DIGESTSIZE ];

	int c;
	string pin;
	cprintf("New PIN:\n");
	while((c = getch()) != (int)'\n') {
		cprintf("*");
		pin += (char)c;
	}
	while(pin.length() != AES::DEFAULT_KEYLENGTH)
		pin += '0';

	endwin();
	hash.CalculateDigest( digest, (byte*) pin.c_str(), pin.length() );

	string hashed_pin;
	ArraySource(digest, true,
			new HexEncoder(
					new StringSink( hashed_pin )));

	string ciphertext;
	byte key[ AES::DEFAULT_KEYLENGTH ];
	StringSource(config_key, true,
			new ArraySink( key, sizeof(key) ));
	EAX< AES >::Encryption enc;

	string enc_keystore_path, enc_keystore_key_number, enc_hashed_pin;
	enc.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
	StringSource( keystore_path, true,
			new AuthenticatedEncryptionFilter( enc,
					new HexEncoder(
							new StringSink( enc_keystore_path ))));
	enc.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
	StringSource( keystore_key_number, true,
			new AuthenticatedEncryptionFilter( enc,
					new HexEncoder(
							new StringSink( enc_keystore_key_number ))));
	enc.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
	StringSource( hashed_pin, true,
			new AuthenticatedEncryptionFilter( enc,
					new HexEncoder(
							new StringSink( enc_hashed_pin ))));

	string config_body = enc_keystore_path + "\n" + enc_keystore_key_number + "\n" + enc_hashed_pin;

	ofstream config_file;
	config_file.open ("config");
	config_file << config_body;
	config_file.close();
}

/* Arguments:
 * 1 - input file
 * 2 - "enc" or "dec"
 */
int main(int argc, char* argv[])
{
	byte iv[ AES::BLOCKSIZE * 16 ] = "000102030405060708090a0b0c0d0e0f";
	string config_key_string = "91945D3F4DCBEE0BF45EF52255F095A4";
	string plain_keystore_key = "91945D3F4DCBEE0BF45EF52255F095A4";

	// Crypto++ AES decryptor and encryptor
	EAX< AES >::Decryption dec;
	EAX< AES >::Encryption enc;

	if(strcmp(argv[1],"key") == 0) {
		generate_key();
		return 0;
	}
	else if(strcmp(argv[1],"config") == 0) {
		generate_config();
		return 0;
	}

	string line, input;
	ifstream input_file (argv[1]);
	if (input_file.is_open()) {
	  while ( getline (input_file,line) )
		  input += line;
	  input_file.close();
	}
	else {
		cout<< "Unable to open input file";
		return 1;
	}

    try {

    	////////////////////////////////////////////////
    	// Read and decrypt config file
    	ifstream config_file ("config");
    	string enc_keystore_path, enc_keystore_key_number_string, enc_config_hashed_pin;
    	// Acquired data which is used later:
    	string keystore_path, keystore_key_number_string, config_hashed_pin;
    	int keystore_key_number;

    	byte config_key[ AES::DEFAULT_KEYLENGTH ];
		StringSource(config_key_string, true,
				new ArraySink( config_key, sizeof(config_key) ));

		if (config_file.is_open())
		{
		  getline (config_file,enc_keystore_path);
		  dec.SetKeyWithIV( config_key, sizeof(config_key), iv, sizeof(iv) );
		  StringSource(enc_keystore_path, true,
				  new HexDecoder(
						  new AuthenticatedDecryptionFilter( dec,
								  new StringSink( keystore_path ))));
		  getline (config_file,enc_keystore_key_number_string);
		  dec.SetKeyWithIV( config_key, sizeof(config_key), iv, sizeof(iv) );
		  StringSource(enc_keystore_key_number_string, true,
				  new HexDecoder(
						  new AuthenticatedDecryptionFilter( dec,
								  new StringSink( keystore_key_number_string ))));
		  keystore_key_number = atoi( keystore_key_number_string.c_str() );
		  getline (config_file,enc_config_hashed_pin);
		  dec.SetKeyWithIV( config_key, sizeof(config_key), iv, sizeof(iv) );
		  StringSource(enc_config_hashed_pin, true,
				  new HexDecoder(
						  new AuthenticatedDecryptionFilter( dec,
								  new StringSink( config_hashed_pin ))));
		  input_file.close();
		}
		else {
			cout<< "Unable to open config file";
			return 1;
		}

		////////////////////////////////////////////////
		// Check PIN
		bool pin_accepted = false;
		string pin;
		int c;
		do {
			cprintf("PIN:\n");
			while((c = getch()) != (int)'\n') {
				cprintf("*");
				pin += (char)c;
			}

			while(pin.length() != AES::DEFAULT_KEYLENGTH)
				pin += '0';

			SHA256 hash;
			byte digest[ SHA256::DIGESTSIZE ];

			hash.CalculateDigest( digest, (byte*) pin.c_str(), pin.length() );

			string hashed_pin;
			ArraySource(digest, true,
				new HexEncoder(
					new StringSink( hashed_pin )));

			if(hashed_pin == config_hashed_pin) {
				pin_accepted = true;
				clear();
				endwin();
			}
			else {
				clear();
				pin= "";
			}
		}
		while(pin_accepted != true);

		////////////////////////////////////////////////
    	// Get encrypted hex key from keystore
    	ifstream keystore_file(keystore_path);
    	string dummy, encoded_hex_key;
		if (keystore_file.is_open())
		{
			// Iterate over other keys
			for(int i = 1; i < keystore_key_number; i++)
				getline( keystore_file, dummy );
			// Get key from right line
			getline( keystore_file, encoded_hex_key );
			input_file.close();
		}
		else {
			cout<< "Unable to open keystore file";
			return 1;
		}

		////////////////////////////////////////////////
		// Unhex key
		string encoded_key;
		StringSource(encoded_hex_key, true,
				new HexDecoder(
						new StringSink( encoded_key )));

		////////////////////////////////////////////////
		// Acquire password from user
		string key_pass;
		cprintf("Key password:\n");
		while((c = getch()) != (int)'\n') {
			cprintf("*");
			key_pass += (char)c;
		}
		endwin();
		while(key_pass.length() != AES::DEFAULT_KEYLENGTH)
			key_pass += '0';

		byte key2key[ AES::DEFAULT_KEYLENGTH ];
		StringSource(key_pass, true,
			new ArraySink( key2key, sizeof(key2key)));

		////////////////////////////////////////////////
		// Decrypt key from keystore
		byte key[ AES::DEFAULT_KEYLENGTH ];
		dec.SetKeyWithIV( key2key, sizeof(key2key), iv, sizeof(iv) );
		StringSource( encoded_key, true,
			new AuthenticatedDecryptionFilter( dec,
				new ArraySink( key, sizeof(key) )));

		////////////////////////////////////////////////
		// Encryption
		string ciphertext;
        if(strcmp(argv[2],"enc") == 0) {

			enc.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

			StringSource( input, true,
				new AuthenticatedEncryptionFilter( enc,
					new StringSink( ciphertext )
				)  // AuthenticatedEncryptionFilter
			); // StringSource

			ofstream enc_file;
			enc_file.open (argv[1]);
			enc_file << ciphertext;
			enc_file.close();
        }

        ////////////////////////////////////////////////
        // Decryption
        else if(strcmp(argv[2],"dec") == 0) {
        	string recovered;
			dec.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

			ArraySource( (byte*)input.data(), input.size(), true,
				new AuthenticatedDecryptionFilter( dec,
					new StringSink( recovered )
				) // AuthenticatedDecryptionFilter
			); //ArraySource

			ofstream enc_file;
			enc_file.open (argv[1]);
			enc_file << recovered;
			enc_file.close();
        }

    } // try

    catch( CryptoPP::Exception&e )
    {
        std::cerr << endl << "Error: " << e.what() << endl;
    }

    return 0;
}




