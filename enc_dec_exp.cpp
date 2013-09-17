/*
   Copyright 2013 Daisuke Miyakawa

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>


using namespace std;

// data to be encrypted with the certificate.
static const char* default_original_data = "default-original-data";

// #define USE_CERTIFICATE
// #define USE_MEMORY_KEY
// #define DECODE_PREENCODED_SRC

#ifdef USE_CERTIFICATE

const char* pub_path = "private/test.crt";
const char* key_path = "private/test.key";

// This header should contain "memory_key" variable, which has
// RSA private key with appropriate line feeds.
// The content should be exactly same as private/test.key (used above).
//
// Note that line feeds are important for OpenSSL.
// PEM is part of MIME, so too long lines are prohibited.
// For Japanese blog post, see http://dmiyakawa.blogspot.jp/2013/02/pem.html
//
// const char* memory_key = "-----BEGIN RSA PRIVATE KEY-----\n
// MII..
// -----END RSA PRIVATE KEY-----";
#include "private/memory_key_cert.h"


#ifdef DECODE_PREENCODED_SRC
// data encoded by test.crt
static const char* preencoded_src =
    "9e4b053c7713019f00c75a5767305b5c28697ee7"
    "c17d1721447df18e9fe9d296bef8585ca8a604f7"
    "083357c113830de7718bd88fd956b9867097d02c"
    "3678b3b79e674a5f30a98b4cc98a98846297a361"
    "221fbccbb68060144577fb6975a736e85f3eeb00"
    "af13c2e707b51764085b40c304a0074d2824cf05"
    "0e2f1f809639573514d1361cda0cfc660797df8a"
    "330b27f73b883549dc7b06b84d14ed2ca78aa3e6"
    "6b73d89bbfd05d7ce54ab93243c05e81d0b11fa8"
    "31f11de07677f08e4790fccecfdaddb1f7aa867c"
    "337a756de75ac660ff7d064c201ef5e99b83739d"
    "01f4a84137597f12f8ef08857dbf359ffff269ab"
    "c2fc7d528acd46fe56eb857a14a202ed";
#endif

#ifdef USE_PASS_PHRASE
#error "Sorry, USE_PASS_PHROSE cannot be used with USE_CERTIFICATE"
#else
const char* pass_phrase = NULL;
#endif

#else // USE_CERTIFICATE

#ifdef USE_PASS_PHRASE

// You can generate other private/public key pairs using openssl command:
// > openssl genrsa -des3 -out data/3des_protected.key
// (enter a pass phrase like "hogehoge")
// > openssl rsa -in data/3des_protected.key -pubout > data/3des_protected.pub
//
// To check contents inside keys, use following commands:
// > openssl rsa -in data/3des_protected.key -noout -text
// (enter the pass phrase)
// > openssl rsa -pubin -in data/3des_protected.pub -noout -text
const char* pass_phrase = "hogehoge";
const char* pub_path = "data/3des_protected.pub";
const char* key_path = "data/3des_protected.key";

#else 

const char* pass_phrase = NULL;
const char* pub_path = "data/raw.pub";
const char* key_path = "data/raw.key";

#endif // USE_PASS_PHRASE


#include "data/memory_key_rsa.h"

#ifdef DECODE_PREENCODED_SRC
// data encoded by test_pub.pem
static const char* preencoded_src =
    "0ebb015e96bda9352c64b2c5cd8d4737e3328a4ea04e5a3ed"
    "bc7cde4565eaee08d21c6f9ee36dbca2950ae1369785b488d"
    "c1790e752be027bdb79553f1725f067b23a27d83d6dbe2bdd"
    "1fe3885e588df33354d5e6e68669fc6967f3bd20996f41090"
    "86d31d3fb93e67603b44d300c0f8868ac4c500bb39500718c"
    "f413bf778ad";
#endif

#endif

int hex2dec(char c) {
    if ('0' <= c && c <= '9') {
        return (int)(c - '0');
    } else if ('A' <= c && c <= 'Z') {
        return (int)(c - 'A') + 10;
    } else if ('a' <= c && c <= 'z') {
        return (int)(c - 'a') + 10;
    }
    return -1;
}

string* hex2str(const char* encoded) {
    size_t len = strlen(encoded);
    if (len % 2 != 0) {
        cerr << "encoded length is inappropriate (must be even number)."
             << endl;
        return NULL;
    }
    ostringstream oss;
    for (size_t i = 0; i < len; i+=2) {
        int n1 = hex2dec(encoded[i]);
        int n2 = hex2dec(encoded[i+1]);
        if (n1 < 0 || n2 < 0) {
            cerr << "unexpect input. encoded=\"" << encoded
                 << "\", i=" << i << endl;
            return NULL;
        }
        oss << (char)((n1 << 4) | n2);
    }
    return new string(oss.str());
}

/*
 * priv_key: correctly initialized private key
 * encrypted: encrypted data in binary form
 */
void decrypt_and_show(EVP_PKEY *priv_key,
                      unsigned char *encrypted,
                      int encrypted_len) {
    RSA* priv_rsa = priv_key->pkey.rsa;
    int max_size = RSA_size(priv_rsa);
    unsigned char* decrypted = new unsigned char[max_size];
    int decrypted_size = RSA_private_decrypt(encrypted_len, encrypted,
                                             decrypted,
                                             priv_rsa, RSA_PKCS1_PADDING);

    //cout << "max_size: " << max_size
    // << ", decrypted_size: " << decrypted_size << endl;

    if (decrypted_size < 0) {
        cerr << "Failed to decrypt the encrypted value." << endl;
    } else {
        cout << "Successfully decrypted the encrypted data." << endl;
        cout << "Decrypted string: \"";
        decrypted[decrypted_size] = '\0';
        for (int i = 0; i < decrypted_size; i++) {
            cout << decrypted[i];
        }
        cout << "\"" << endl;
    }
    delete [] decrypted;
}

void enc_dec_exp(const char* original_data) {
    EVP_PKEY * pub_key = NULL;

    BIO *bio2 = NULL;
    EVP_PKEY *priv_key = NULL;

    unsigned char* encrypted = NULL;
    int encrypted_size;

#ifdef USE_CERTIFICATE
    STACK_OF(X509) *certs = NULL;
    X509 *cert = NULL;
    FILE *cert_fp = NULL;
#else

#endif

#ifdef USE_MEMORY_KEY
    char *buf = NULL;
#endif

    // Initialize misc stuff.
    // For this exact case, some are not needed.
    SSL_library_init();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    cout << "Original string (that will be encoded/decoded): \""
         << original_data
         << "\""
         << endl << endl;

#ifdef USE_CERTIFICATE
    cout << "Obtaining a X509 certificate from \""
         << pub_path
         << "\"" << endl;

    cert_fp = fopen(pub_path, "r");
    if (!cert_fp) {
        cerr << "Failed to open \"" << pub_path << "\"" << endl;
        goto free;
    }
    certs = sk_X509_new_null();
    cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    if (!cert) {
        cerr << "Failed to create X509 object from \""
             << pub_path << "\"" << endl;
    }
    pub_key = (EVP_PKEY *) X509_get_pubkey(cert);
#else
    cout << "Obtaining a public key from \""
         << pub_path
         << "\"" << endl;

    {
        BIO *in;
        in = BIO_new_file(pub_path, "r");
        pub_key = PEM_read_bio_PUBKEY(in, NULL,NULL, NULL);
        BIO_free(in);
    }
#endif

    if (!pub_key) {
        cerr << "Failed to read pub_key" << endl;
        goto free;
    }

    cout << "Successfully obtained a public key. "
         << "Public key type: ";
    switch (pub_key->type) {
    case EVP_PKEY_RSA:
        cout << "rsa" << endl;
        break;
    case EVP_PKEY_RSA2:
        cout << "rsa2" << endl;
        break;
    default:
        cout << "unknown" << endl;
    }
    cout << "Try to encrypt the original string."
         << endl << endl;

    if (!pub_key->pkey.rsa) {
        cerr << "Cannot obtain RSA object from pub_key" << endl;
        goto free;
    }
    encrypted = new unsigned char[RSA_size(pub_key->pkey.rsa)];
    encrypted_size = RSA_public_encrypt(strlen(original_data),
                                        (unsigned char*)original_data,
                                        encrypted,
                                        pub_key->pkey.rsa,
                                        RSA_PKCS1_PADDING);

    if (encrypted_size < 0) {
        cerr << "Failed to encrypt a given value." << endl;
        ERR_load_crypto_strings();
        cerr << "Reason from OpenSSL library: \""
             << ERR_reason_error_string(ERR_get_error())
             << "\"" << endl;
        ERR_free_strings();
        goto free;
    }

    {
        ostringstream ss;
        ss << hex << setfill( '0' );
        for (int i = 0; i < encrypted_size; i++) {
            int c = (int)encrypted[i];
            ss << std::setw( 2 ) << c;
        }
        cout << "Encryption successful" << endl;
        cout << "Information about the encrypted data:" << endl;
        cout << "  size=" << encrypted_size << endl;
        cout << "  hex-encoded=\"" << ss.str() << "\"" << endl;
    }
    cout << endl;

    cout << "Next, obtain a private key associated with the public key. "
         << endl;

#ifdef USE_MEMORY_KEY
    cout << "This example will use a private key stored in the program."
         << endl;
    buf = new char[strlen(memory_key) + 1];
    strcpy(buf, memory_key);
    bio2 = BIO_new_mem_buf(buf, -1);
#else
    cout << "This example will use a private key stored in the file \""
         << key_path
         << "\"" << endl;
    bio2 = BIO_new_file(key_path, "r");
#endif

    if (pass_phrase == NULL) {
        cout << "No pass phrase is specified." << endl;
        priv_key = PEM_read_bio_PrivateKey(bio2, NULL,NULL, NULL);
    } else {
        cerr << "Will use pass phrase \"" << pass_phrase << "\"" << endl;
        char *copied_pass_phrase = new char[strlen(pass_phrase)+1];
        strcpy(copied_pass_phrase, pass_phrase);
        priv_key = PEM_read_bio_PrivateKey(bio2, NULL,NULL,
                                           copied_pass_phrase);
        delete[] copied_pass_phrase;
    }
    cout << endl;

    if (priv_key == NULL) {
        cerr << "Failed to obtain a private key." << endl;
        ERR_load_crypto_strings();
        cerr << "Reason from OpenSSL library: \""
             << ERR_reason_error_string(ERR_get_error())
             << "\"" << endl;
        ERR_free_strings();
        goto free;
    }

    cout << "Successfully obtained a private key." << endl;
    cout << "Try to decrypt the encrypted data, and obtain the original."
         << endl
         << endl;

    decrypt_and_show(priv_key, encrypted, encrypted_size);

    cout << endl;
    cout << "Demonstration done. Check if the original string and "
         << "the decrypted one is exactly same."
         << endl << endl;

#ifdef DECODE_PREENCODED_SRC
    {
        string* bin = hex2str(preencoded_src);
        int bin_size = bin->size();
        unsigned char* copied_src = new unsigned char[bin_size+1];
        for (int i = 0; i < bin_size; i++) {
            copied_src[i] = (unsigned char)bin->at(i);
        }
        copied_src[bin_size] = '\0';
        decrypt_and_show(priv_key, copied_src, bin_size);
        delete [] copied_src;
        delete bin;
    }
#endif

 free:
#ifdef USE_MEMORY_KEY
    if (buf) {
        delete [] buf;
    }
#endif
    if (encrypted) {
        delete [] encrypted;
    }

    if (priv_key) {
        EVP_PKEY_free(priv_key);
    }
    if (bio2) {
        BIO_free(bio2);
    }

#ifdef USE_CERTIFICATE
    if (pub_key) {
        // It looks we don't need to call EVP_PKEY_Free()
        // when pub_key is obtained via X509_get_pubkey().
        // EVP_PKEY_free(pub_key);
    }
    if (cert) {
        X509_free(cert);
    }
    if (certs) {
        sk_X509_delete(certs, 0);
        sk_X509_free(certs);
    }
    if (cert_fp) {
        fclose(cert_fp);
    }

#else
    if (pub_key) {
        EVP_PKEY_free(pub_key);
    }
#endif
}

int main(int argc, char **argv) {
    cout << "This program will demonstrate how a given string will be "
         << "encrypted and decrypted using a provided RSA key pair."
         << endl;
    if (argc < 2) {
        cout << "Note: you can specify a string to be encrypted/decrypted "
             << "using an argument."
             << endl << endl;
        enc_dec_exp(default_original_data);
    } else {
        cout << endl;
        enc_dec_exp(argv[1]);
    }
    return 0;
}
