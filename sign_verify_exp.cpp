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
/*
  Experimental program which demonstrates signing/verifying a simple text
  message.
  By default this program will use a public/private key pair stored in data/.
  If you want to use X509 certificate and its private key, you need to
  prepare them by yourself.
 */

#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

const char* default_message  = "Default Test Message";

const EVP_MD *evp_md_sha1 = EVP_sha1();

// TODO: similar to enc_dec_exp. We may share the logic somewhere else.
#ifdef USE_CERTIFICATE
const char* cert_path = "private/test.crt";
const char* priv_key_path = "private/test.key";
#else
const char* pub_key_path = "data/rsa_pubkey.pem";
const char* priv_key_path = "data/rsa_privkey.pem";
#endif



class sign_result {
public:
    bool success;
    unsigned char *sig;
    size_t sig_len;

    static sign_result* obtain() {
        sign_result *result = new sign_result();
        result->success = false;
        return result;
    }

    static void release(sign_result *result) {
        if (result->sig) {
            delete [] result->sig;
        }
        delete result;
    }
};

sign_result* sign(const char* message) {
    sign_result *result = sign_result::obtain();
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *priv_key = NULL;
    BIO *bio = NULL;
    int ret;

    md_ctx = EVP_MD_CTX_create();
    bio = BIO_new_file(priv_key_path, "r");
    priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    // Initialize EVP_MD_CTX with
    //  - a private key prepared above, and
    //  - a default engine (NULL).
    // SHA1 will be used for exact algorithm.
    // If EVP_PKEY_CTX object is needed we can specify the second argument.
    // The object is actually part of md_ctx, so we should not free it
    // manually. EVP_MD_CTX_destroy() will take care of freeing it.
    ret = EVP_DigestSignInit(md_ctx, NULL, evp_md_sha1, NULL, priv_key);
    if (ret != 1) {
        cerr << "Failed to call EVP_DigestSignInit(). ret=" << ret << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    // Hash the message. This function can be called multiple times with
    // different messages.
    ret = EVP_DigestSignUpdate(md_ctx, message, strlen(message)); 
    if (ret != 1) {
        cerr << "Failed to call EVP_DigestSignUpdate(). ret=" << ret << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }
    
    // Obtain the necessary length for signature.
    ret = EVP_DigestSignFinal(md_ctx, NULL, &result->sig_len);
    if (ret != 1) {
        cerr << "Failed to call EVP_DigestSignFinal() with NULL buffer."
             << " ret=" << ret << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    // Now obtain the content by calling EVP_DigestSignFinal() again
    // with data buffer with the specified length.
    result->sig = new unsigned char[result->sig_len];
    cout << "size: " << result->sig_len << endl;
    if (!EVP_DigestSignFinal(md_ctx, result->sig, &result->sig_len)) {
        cerr << "Failed to call EVP_DigestSignFinal()" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    {
        ostringstream ss;
        ss << hex << setfill( '0' );
        for (size_t i = 0; i < result->sig_len; i++) {
            ss << std::setw( 2 ) << (int)result->sig[i];
        }
        cout << "Signed Digest: " << ss.str() << endl;
    }

    result->success = true;
 free:

    if (md_ctx) {
        EVP_MD_CTX_destroy(md_ctx);
    }
    if (priv_key) {
        EVP_PKEY_free(priv_key);
    }
    if (bio) {
        BIO_free(bio);
    }

    return result;
}

bool verify(const char *message, unsigned char* sig, size_t sig_len) {
    bool result = false;

    EVP_PKEY * pub_key = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    int ret;

#ifdef USE_CERTIFICATE
    STACK_OF(X509) *certs = NULL;
    X509 *cert = NULL;
    FILE *cert_fp = NULL;
#endif


#ifdef USE_CERTIFICATE
    // Load a certificate and retrieve a public key from it.
    cert_fp = fopen(cert_path, "r");
    if (!cert_fp) {
        cerr << "Failed to open \"" << cert_path << "\"" << endl;
        goto free;
    }
    certs = sk_X509_new_null();
    cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    if (!cert) {
        cerr << "Failed to create X509 object from \""
             << cert_path << "\"" << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }
    pub_key = (EVP_PKEY *)X509_get_pubkey(cert);
#else // USE_CERTIFICATE
    {
        BIO *in;
        in = BIO_new_file(pub_key_path, "r");
        pub_key = PEM_read_bio_PUBKEY(in, NULL,NULL, NULL);
        BIO_free(in);
    }
#endif

    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx) {
        cerr << "Failed to obtain EVP_MD_CTX" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    ret = EVP_DigestVerifyInit(md_ctx, NULL, evp_md_sha1, NULL, pub_key);
    if (ret != 1) {
        cerr << "EVP_DigestVerifyInit() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    ret = EVP_DigestVerifyUpdate(md_ctx, message, strlen(message));
    if (ret != 1) {
        cerr << "EVP_DigestVerifyUpdate() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    ret = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
    if (ret != 1) {
        cerr << "EVP_DigestVerifyFinal() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }
    cout << "Verification successful" << endl;

    result = true;
 free:

    if (md_ctx) {
        EVP_MD_CTX_destroy(md_ctx);
    }

#ifdef USE_CERTIFICATE
    if (pub_key) {
        // It looks we don't need to call EVP_PKEY_Free().
        // pub_key is part of the certificate.
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

    return result;
}

int main(int argc, char** argv) {
    const char* message;
    if (argc > 1) {
        message = argv[1];
    } else {
        message = default_message;
    }
    cout << "Will use \"" << message << "\" as a message to sign" << endl;
    cout << endl;

    sign_result* result = sign(message);
    if (!result->success) {
        cerr << "sign() failed" << endl;
        sign_result::release(result);
        return 1;
    }
    cout << endl;
    if (!verify(message, result->sig, result->sig_len)) {
        cerr << "verify() failed" << endl;
        return 1;
    }

    sign_result::release(result);
    return 0;
}
