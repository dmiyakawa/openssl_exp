#include <iostream>
#include <cstring>
#include <sstream>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

const char* message  = "Test Message\n";
const char* wrong_message  = "Wrong Message\n";

const char* cert_path = "private/test.crt";
const char* key_path = "private/test.key";
const EVP_MD *evp_md_sha1 = EVP_sha1();

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

sign_result* sign() {
    sign_result *result = sign_result::obtain();
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY *priv_key = NULL;
    BIO *bio = NULL;

    md_ctx = EVP_MD_CTX_create();
    bio = BIO_new_file(key_path, "r");
    priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    // Initialize EVP_MD_CTX with
    //  - a private key prepared above, and
    //  - a default engine (NULL).
    // SHA1 will be used for exact algorithm.
    // If EVP_PKEY_CTX object is needed we can specify the second argument.
    // The object is actually part of md_ctx, so we should not free it
    // manually. EVP_MD_CTX_destroy() will take care of freeing it.
    if (!EVP_DigestSignInit(md_ctx, NULL, evp_md_sha1, NULL, priv_key)) {
        cerr << "Failed to call EVP_DigestSignInit()" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    if (!EVP_DigestSignUpdate(md_ctx, message, strlen(message))) {
        cerr << "Failed to call EVP_DigestSignUpdate()" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }
    
    // First obtain the necessary length for signature.
    if (!EVP_DigestSignFinal(md_ctx, NULL, &result->sig_len)) {
        cerr << "Failed to call EVP_DigestSignFinal() with NULL buffer" << endl;
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

bool verify(unsigned char* sig, size_t sig_len) {
    bool result = false;

    EVP_PKEY * pub_key = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    STACK_OF(X509) *certs = NULL;
    X509 *cert = NULL;
    FILE *cert_fp = NULL;
    int ret;

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

    md_ctx = EVP_MD_CTX_create();
    if (!md_ctx) {
        cerr << "Failed to obtain EVP_MD_CTX" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    pkey_ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!pkey_ctx) {
        cerr << "Failed to obtain EVP_PKEY_CTX" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        goto free;
    }

    ret = EVP_DigestVerifyInit(md_ctx, &pkey_ctx,
                               evp_md_sha1, NULL, pub_key);
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
        pkey_ctx = NULL;
    }
    if (pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
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

    return result;
}

int main() {
    sign_result* result = sign();
    if (!result->success) {
        cerr << "sign() failed" << endl;
        sign_result::release(result);
        return 1;
    }
    cout << endl;
    if (!verify(result->sig, result->sig_len)) {
        cerr << "verify() failed" << endl;
        return 1;
    }

    sign_result::release(result);
    return 0;
}
