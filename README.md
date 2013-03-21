OpenSSL experimental programs

* dh_exp: Diffie-Hellman key exchange
* enc_dec_exp: encoding/decoding with X509 cert/key or RSA pub/priv key
* rsa_exp: creating an RSA pub/priv key pair
* sign_verify_exp.cpp: signining/verifying a simple text with RSA priv/pub key
* openssl.php: A simple script using OpenSSL functions in PHP. Very rough.

Note that you need to prepare X509 cert/key pair to try enc_dec_exp.
The certificate is (probably) ok to be self-signed.
