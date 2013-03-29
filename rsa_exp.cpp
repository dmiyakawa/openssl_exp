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
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <iostream>

using namespace std;

char* generate_key_pair() {
    RSA* rsa = NULL;
    BIO* bio_priv = NULL;
    BIO* bio_pub = NULL;
    BUF_MEM *bptr_priv = NULL;
    BUF_MEM *bptr_pub = NULL;
    char* ret = NULL;

    rsa = RSA_generate_key(1024, RSA_3, NULL, NULL);
    if (RSA_check_key(rsa) != 1) {
        goto free;
    }

    bio_priv = BIO_new(BIO_s_mem());
    bio_pub = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_RSAPrivateKey(bio_priv, rsa, NULL, NULL, 0, 0, NULL)) {
        goto free;
    }

    /*
      Here's descriptions in "man PEM"
      --
      The RSAPublicKey functions process an RSA public key using an
      RSA structure. The public key is encoded using a PKCS#1 RSAPublicKey
      structure.

      The RSA_PUBKEY functions also process an RSA public key using an RSA
      structure. However the public key is encoded using a
      SubjectPublicKeyInfo structure and an error occurs if the public key
      is not RSA.
      --
      If you want to let other components outside OpenSSL (e.g. Java), you
      probably want to use PEM_write_bio_RSA_PUBKEY(), which is
      along with RFC2313.
    */ 
    if (!PEM_write_bio_RSA_PUBKEY(bio_pub, rsa)) {
        // if (!PEM_write_bio_RSAPublicKey(bio_pub, rsa)) {
        goto free;
    }
    BIO_get_mem_ptr(bio_priv, &bptr_priv);
    BIO_get_mem_ptr(bio_pub, &bptr_pub);
    ret = (char *)malloc(bptr_priv->length + bptr_pub->length + 1);
    memcpy(ret, bptr_priv->data, bptr_priv->length);
    memcpy(ret + bptr_priv->length, bptr_pub->data, bptr_pub->length);
    ret[bptr_priv->length + bptr_pub->length] = '\0';

 free:
    if (bio_pub) {
        BIO_free(bio_pub);
    }
    if (bio_priv) {
        BIO_free(bio_priv);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    return ret;
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();

    char* data = generate_key_pair();
    cerr << data << endl;
    free(data);

    return 0;
}
