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
#include <boost/algorithm/string.hpp>
#include <boost/scoped_ptr.hpp>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/dh.h>
#include <openssl/err.h>
using namespace std;

#ifdef SIDE2_DEFINED_OUTSIDE
// In this scenario side2 is defined by another component.
// We assume it already shares p and g, sending this code
// its own public key (side2_pub_key_str).
//
// Theoretically we should be able to calculate a shared secret
// just with p, g, side1_priv, and side2_pub (*without* side2_priv).

static const char* p_str = "aea2358d43e5c7119ea455a030dcc2763bf4e64a91d25e75abb0791c2ec797a7374c9b2d7804d8e744181c99afba93271539e9b6051f7204b9225386f209d7bf";
static const char* g_str = "05";

static const char* side1_priv_key_str =
    "2bc1e88c53be1b6d4d1d049ad5606dc940250d031e8442437"
    "0b67818c55dda81469e6610efd841902a60f4e17c52f947";
static const char* side1_pub_key_str =
    "39b15346ad62891a8224e3d46868041b41fc4fe7788375344"
    "2b6d2a1bf2eb10990588a1df87c10951d6eef4188fc69f2ff"
    "ecedee7fbcc254120f99436419acfd";

static const char* side2_pub_key_str =
    "286a85231814f98f9547126835eebd10127212966eb8b21d9"
    "956c3c33eddd0b6a163801ac3e91633669d9f2468b4d50ccb"
    "0c525b75207592944ebc809304c14a";

static const char* expected_shared_secret =
    "9e239d19acbae66d117a9643d0599682c118020563b93664e"
    "be33f4d9e2353b43ab6ed7811d1b47c552c1601eac0f642cc"
    "3e96fc54acdff3f70208b8a016f0d0";
#endif  // SIDE2_DEFINED_OUTSIDE

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

void print_dh(DH *dh) {
    string p, g, pub_key, priv_key;
    {
        char *p_tmp = BN_bn2hex(dh->p);
        char *g_tmp = BN_bn2hex(dh->g);
        char *pub_key_tmp = BN_bn2hex(dh->pub_key);
        char *priv_key_tmp = BN_bn2hex(dh->priv_key);
        p = string(p_tmp);
        g = string(g_tmp);
        pub_key = string(pub_key_tmp);
        priv_key = string(priv_key_tmp);
        boost::algorithm::to_lower(p);
        boost::algorithm::to_lower(g);
        boost::algorithm::to_lower(pub_key);
        boost::algorithm::to_lower(priv_key);
        OPENSSL_free(p_tmp);
        OPENSSL_free(g_tmp);
        OPENSSL_free(pub_key_tmp);
        OPENSSL_free(priv_key_tmp);
    }
    cout << "p=" << p << endl;
    cout << "g=" << g << endl;
    cout << "pub_key=" << pub_key << endl;
    cout << "priv_key=" << priv_key << endl;
    cout << endl;

    DHparams_print_fp(stdout, dh);
}

/*
 * Caller must free a returned pointer
 */
string* obtain_shared_secret(DH *dh, BIGNUM * pub_key) {
    unsigned char* secret_cstr = new unsigned char[DH_size(dh)];
    int ret = DH_compute_key(secret_cstr, pub_key, dh);
    if (ret < 0) {
        cerr << "DH_compute_key() failed. ret=" << ret << endl;
        int e = ERR_get_error();
        ERR_load_crypto_strings();
        cerr << ERR_reason_error_string(e) << endl;
        ERR_free_strings();

        delete[] secret_cstr;
        return NULL;
    }
    ostringstream ss;
    ss << hex << setfill( '0' );
    for (int i = 0; i < ret; i++) {
        int c = (int)secret_cstr[i];
        ss << std::setw( 2 ) << c;
    }
    delete[] secret_cstr;
    return new string(ss.str());
}

void dh_experiment() {
    DH* dh_side1 = NULL;
    boost::scoped_ptr<string> secret_side1;

#ifdef SIDE2_DEFINED_OUTSIDE
    BIGNUM* side2_pub_key = NULL;
#else
    DH* dh_side2 = NULL;
    boost::scoped_ptr<string> secret_side2;
#endif

#ifdef SIDE2_DEFINED_OUTSIDE
    cout << "Will use pre-installed values." << endl << endl;
#else
    cout << "Will create DH params for both side1 and side2." << endl << endl;
#endif

    /*** Prepare side1 ***/

    dh_side1 = DH_new();
    if (!dh_side1) {
        cerr << "dh_side1 is null." << endl;
        goto free;
    }

#ifdef SIDE2_DEFINED_OUTSIDE
    // Copy predefined values from constants.
    BN_hex2bn(&dh_side1->p, p_str);
    BN_hex2bn(&dh_side1->g, g_str);
    BN_hex2bn(&dh_side1->priv_key, side1_priv_key_str);
    BN_hex2bn(&dh_side1->pub_key, side1_pub_key_str);
#else
    // Dynamically generate p and g
    if (!DH_generate_parameters_ex(dh_side1, 512, DH_GENERATOR_5, 0)) {
        cerr << "DH_generate_parameters_ex() failed." << endl;
        goto free;
    }
#endif

    // Check if given values are sane.
    {
        int codes = 0;
        if (!DH_check(dh_side1, &codes)) {
            cerr << "DH_check() for dh_side1 failed" << endl;
            goto free;
        }
        if (codes != 0) {
            cerr << "WARNING: DH_check() returned non-0 codes: "
                 << codes << endl;
        }
    }

    /*** Prepare side2 ***/

#ifdef SIDE2_DEFINED_OUTSIDE
    // Use pre-installed side2_pub_key from a constant.
    // Do not need, or actually cannot rely on DH object for side2.
    // We assume that values for side2 are generated outside this code,
    // especially private value for side2.
    //
    // What we get is public value for side2, which is available from
    // side2_pub_key_str.
    side2_pub_key = BN_new();
    BN_init(side2_pub_key);
    BN_hex2bn(&side2_pub_key, side2_pub_key_str);
#else
    // Similar to side1, generate DH object for side2.
    // This time p and g should be same as what in dh_side1.
    dh_side2 = DH_new();
    if (!dh_side2) {
        cerr << "dh_side2 is null." << endl;
        goto free;
    }
    dh_side2->p = BN_new();
    dh_side2->g = BN_new();
    if (!(BN_copy(dh_side2->p, dh_side1->p)
          && BN_copy(dh_side2->g, dh_side1->g))) {
        cerr << "Failed to copy p/g" << endl;
        goto free;
    }

    // Both side1 and side2 generate private/public keys.
    if (!(DH_generate_key(dh_side1)
          && DH_generate_key(dh_side2))) {
        cerr << "DH_generate_key() failed" << endl;
        goto free;
    }
#endif

    cout << "---dh_side1---" << endl;
    print_dh(dh_side1);
    cout << endl;

#ifdef SIDE2_DEFINED_OUTSIDE

    cout << "---dh_side2 (outside this code) ---" << endl;
    cout << "pub_key=" << side2_pub_key_str << endl;
    cout << endl;

    // Calcurate a shared secret using dh_side1 and side2's public key.
    secret_side1.reset(obtain_shared_secret(dh_side1, side2_pub_key));
    if (!secret_side1.get()) {
        cout << "Failed to obtain shared secret for side1" << endl;
    } else if (*secret_side1 != expected_shared_secret) {
        cout << "Shared secret is different from what side2 has.." << endl;
        cout << "expected: " << expected_shared_secret << endl;
        cout << "actual: " << *secret_side1 << endl;
    } else {
        cout << "resultant shared secret=" << *secret_side1 << endl;
    }
#else

    cout << "---dh_side2---" << endl;
    print_dh(dh_side2);
    cout << endl;

    secret_side1.reset(obtain_shared_secret(dh_side1, dh_side2->pub_key));
    secret_side2.reset(obtain_shared_secret(dh_side2, dh_side1->pub_key));
    if (!secret_side1.get()) {
        cout << "Failed to obtain shared secret for side1" << endl;
    } else if (!secret_side2.get()) {
        cout << "Failed to obtain shared secret for side2" << endl;
    } else  if (*secret_side1 != *secret_side2) {
        // Two secrets from both sides should match.
        cout << "Shared secret didn't match.." << endl;
    } else {
        // Successful case.
        cout << "resultant shared secret=" << *secret_side1 << endl;
    }
#endif


 free:
#ifdef SIDE2_DEFINED_OUTSIDE
    if (side2_pub_key) {
        BN_clear_free(side2_pub_key);
    }
#else
    if (dh_side2) {
        // Although we prepared p and g outsude DH_new()
        // (by calling BN_new() separately),
        // just calling DH_free(dh_side2) is enough here.
        // DH_free() will take care of them too.
        DH_free(dh_side2);
    }
#endif
    if (dh_side1) {
        DH_free(dh_side1);
    }
}

int main(int argc, char *argv[]) {
    dh_experiment();
}

