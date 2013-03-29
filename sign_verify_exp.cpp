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
#include <memory>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

// #define USE_CERTIFICATE
// #define USE_DYNAMIC_KEY

auto del_bio = [](BIO *bio) {
    BIO_free(bio);
};

auto del_md_ctx = [](EVP_MD_CTX *md_ctx) {
    EVP_MD_CTX_destroy(md_ctx);
};

auto del_file = [](FILE *fp) {
    fclose(fp);
};

auto del_evp_pkey = [](EVP_PKEY *key) {
    EVP_PKEY_free(key);
};

auto noop_evp_pkey = [](EVP_PKEY *key) {
};

auto del_cert = [](X509 *cert) {
    X509_free(cert);
};

auto del_certs = [](STACK_OF(X509) *certs) {
    sk_X509_delete(certs, 0);
    sk_X509_free(certs);
};

auto del_rsa = [](RSA *p) {
    RSA_free(p);
};

auto del_bignum = [](BIGNUM *p) {
    BN_clear_free(p);
};

const char* default_message  = "Default Test Message";
const EVP_MD *evp_md_sha1 = EVP_sha1();

class key_pair {
public:
#if defined(USE_CERTIFICATE)
    unique_ptr<EVP_PKEY, decltype(del_evp_pkey)> priv_key_;
    unique_ptr<EVP_PKEY, decltype(noop_evp_pkey)> pub_key_;
    unique_ptr<STACK_OF(X509), decltype(del_certs)> certs_;
    unique_ptr<X509, decltype(del_cert)> cert_;
    key_pair() : priv_key_(NULL, del_evp_pkey), pub_key_(NULL, noop_evp_pkey),
                 certs_(NULL, del_certs), cert_(NULL, del_cert) {
    }
#elif defined(USE_DYNAMIC_KEY)
    unique_ptr<EVP_PKEY, decltype(del_evp_pkey)> priv_key_;
    unique_ptr<EVP_PKEY, decltype(noop_evp_pkey)> pub_key_;
    key_pair() : priv_key_(NULL, del_evp_pkey), pub_key_(NULL, noop_evp_pkey){
    }
#else
    unique_ptr<EVP_PKEY, decltype(del_evp_pkey)> priv_key_;
    unique_ptr<EVP_PKEY, decltype(del_evp_pkey)> pub_key_;

    key_pair() : priv_key_(NULL, del_evp_pkey), pub_key_(NULL, del_evp_pkey){
    }
#endif
    virtual ~key_pair() {
    }

    /*
     * Returns a valid key_pair object when successful.
     * Returns NULL when not successful.
     */
    static key_pair* construct();
};

#if defined(USE_CERTIFICATE)
const char* cert_path = "private/test.crt";
const char* priv_key_path = "private/test.key";

key_pair* key_pair::construct() {
    unique_ptr<key_pair> pair(new key_pair());
    unique_ptr<BIO, decltype(del_bio)> bio(BIO_new_file(priv_key_path, "r"),
                                           del_bio);
    if (bio.get()) {
        pair->priv_key_.reset(PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL));
        if (!pair->priv_key_) {
            return NULL;
        }
    }

    // Load a certificate and retrieve a public key from it.
    unique_ptr<FILE, decltype(del_file)> cert_fp(fopen(cert_path, "r"),
                                                 del_file);
    if (!cert_fp.get()) {
        cerr << "Failed to open \"" << cert_path << "\"" << endl;
        return NULL;
    }
    pair->certs_.reset(sk_X509_new_null());
    pair->cert_.reset(PEM_read_X509(cert_fp.get(), NULL, NULL, NULL));
    if (!pair->cert_) {
        cerr << "Failed to create X509 object from \""
             << cert_path << "\"" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return NULL;
    }

    // Note: no need to manually free this.
    pair->pub_key_.reset((EVP_PKEY *) X509_get_pubkey(pair->cert_.get()));

    return pair.release();
}

#elif defined(USE_DYNAMIC_KEY)
key_pair* key_pair::construct() {
    int ret;
    unique_ptr<key_pair> pair(new key_pair());
    unique_ptr<RSA, decltype(del_rsa)> rsa(RSA_new(), del_rsa);
    unique_ptr<BIGNUM, decltype(del_bignum)> f4(BN_new(), del_bignum);

    BN_set_word(f4.get(), RSA_F4);
    ret = RSA_generate_key_ex(rsa.get(), 1024, f4.get(), NULL);
    if (ret != 1) {
        cerr << "Failed to call RSA_generate_key_ex(). ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return NULL;
    }
    ret = RSA_check_key(rsa.get());
    if (ret != 1) {
        cerr << "RSA_check_key() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return NULL;
    }

    pair->priv_key_.reset(EVP_PKEY_new());
    pair->pub_key_.reset(pair->priv_key_.get());

    // rsa should be freed manually (unlike EVP_PKEY_assign_RSA())
    ret = EVP_PKEY_set1_RSA(pair->priv_key_.get(), rsa.get());
    if (ret != 1) {
        cerr << "EVP_PKEY_set1_RSA() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return NULL;
    }

    return pair.release();
}

#else
const char* pub_key_path = "data/rsa_pubkey.pem";
const char* priv_key_path = "data/rsa_privkey.pem";
key_pair* key_pair::construct() {
    unique_ptr<key_pair> pair(new key_pair());
    unique_ptr<BIO, decltype(del_bio)> bio_priv(BIO_new_file(priv_key_path, "r"),
                                                del_bio);
    if (bio_priv) {
        pair->priv_key_.reset(PEM_read_bio_PrivateKey(bio_priv.get(),
                                                      NULL, NULL, NULL));
        if (!pair->priv_key_) {
            return NULL;
        }
    }

    unique_ptr<BIO, decltype(del_bio)> bio_pub(BIO_new_file(pub_key_path, "r"),
                                                del_bio);
    // bio_pub = BIO_new_file(pub_key_path, "r");
    if (bio_pub) {
        pair->pub_key_.reset(PEM_read_bio_PUBKEY(bio_pub.get(),
                                                 NULL,NULL, NULL));
        if (!pair->pub_key_) {
            return NULL;
        }
    }

    return pair.release();
}
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

sign_result* sign(EVP_PKEY* priv_key, const char* message) {
    sign_result *result = sign_result::obtain();
    // EVP_PKEY *priv_key = NULL;
    // BIO *bio = NULL;
    int ret;

    unique_ptr<EVP_MD_CTX, decltype(del_md_ctx)>
        md_ctx(EVP_MD_CTX_create(), del_md_ctx);
    /*bio = BIO_new_file(priv_key_path, "r");
      priv_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);*/

    // Initialize EVP_MD_CTX with
    //  - a private key prepared above, and
    //  - a default engine (NULL).
    // SHA1 will be used for exact algorithm.
    // If EVP_PKEY_CTX object is needed we can specify the second argument.
    // The object is actually part of md_ctx, so we should not free it
    // manually. EVP_MD_CTX_destroy() will take care of freeing it.
    ret = EVP_DigestSignInit(md_ctx.get(), NULL, evp_md_sha1, NULL, priv_key);
    if (ret != 1) {
        cerr << "Failed to call EVP_DigestSignInit(). ret=" << ret << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return result;
    }

    // Hash the message. This function can be called multiple times with
    // different messages.
    ret = EVP_DigestSignUpdate(md_ctx.get(), message, strlen(message)); 
    if (ret != 1) {
        cerr << "Failed to call EVP_DigestSignUpdate(). ret=" << ret << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return result;
    }
    
    // Obtain the necessary length for signature.
    ret = EVP_DigestSignFinal(md_ctx.get(), NULL, &result->sig_len);
    if (ret != 1) {
        cerr << "Failed to call EVP_DigestSignFinal() with NULL buffer."
             << " ret=" << ret << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return result;
    }

    // Now obtain the content by calling EVP_DigestSignFinal() again
    // with data buffer with the specified length.
    result->sig = new unsigned char[result->sig_len];
    cout << "size: " << result->sig_len << endl;
    if (!EVP_DigestSignFinal(md_ctx.get(), result->sig, &result->sig_len)) {
        cerr << "Failed to call EVP_DigestSignFinal()" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return result;
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
    return result;
}


bool verify(EVP_PKEY * pub_key, const char *message,
            unsigned char* sig, size_t sig_len) {
    unique_ptr<EVP_MD_CTX, decltype(del_md_ctx)>
        md_ctx(EVP_MD_CTX_create(), del_md_ctx);
    if (!md_ctx) {
        cerr << "Failed to obtain EVP_MD_CTX" << endl;
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return false;
    }
    int ret = EVP_DigestVerifyInit(md_ctx.get(), NULL, evp_md_sha1,
                                   NULL, pub_key);
    if (ret != 1) {
        cerr << "EVP_DigestVerifyInit() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return false;
    }

    ret = EVP_DigestVerifyUpdate(md_ctx.get(), message, strlen(message));
    if (ret != 1) {
        cerr << "EVP_DigestVerifyUpdate() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return false;
    }

    ret = EVP_DigestVerifyFinal(md_ctx.get(), sig, sig_len);
    if (ret != 1) {
        cerr << "EVP_DigestVerifyFinal() failed. ret=" << ret << endl;

        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(ERR_get_error()) << endl;
        ERR_free_strings();
        return false;
    }
    cout << "Verification successful" << endl;

    return true;
}

int main(int argc, char** argv) {
    int ret = 1;

    const char* message;
    if (argc > 1) {
        message = argv[1];
    } else {
        message = default_message;
    }
    cout << "Will use \"" << message << "\" as a message to sign" << endl;
    cout << endl;

    sign_result* result = NULL;
    unique_ptr<key_pair> pair(key_pair::construct());

    if (!pair.get()) {
        cerr << "Failed to construct pair" << endl;
        goto free;
    }

    result = sign(pair->priv_key_.get(), message);
    if (!result->success) {
        cerr << "sign() failed" << endl;
        goto free;
    }
    cout << endl;
    if (!verify(pair->pub_key_.get(), message, result->sig, result->sig_len)) {
        cerr << "verify() failed" << endl;
        goto free;
    }

    ret = 0;
 free:
    if (result) {
        sign_result::release(result);
    }
    return ret;
}
