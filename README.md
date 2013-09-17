# What is this?

OpenSSL experimental programs, written in C++.
Hopefully you will understand how OpenSSL library can be used with C++.

Lisensed under the Apache License 2.0.

Tested with Debian squeeze and wheezy.

## List of contents

* dh_exp: Diffie-Hellman key exchange
* enc\_dec\_exp: encoding/decoding with X509 cert/key or RSA pub/priv key
* rsa_exp: creating an RSA pub/priv key pair
* sign\_verify\_exp.cpp: signining/verifying a simple text with RSA priv/pub key
* openssl.php: A simple script using OpenSSL functions in PHP. Very rough.

### dh_exp.cpp

This demonstrates Diffie-Hellman key exchange.

(to be documented more..)

## enc_dec_exp.cpp

This demonstrates how to encrypt a single text using OpenSSL public key and decrypt it 
using OpenSSL private key. You may apply the technique toward files too
(with appropriate modifications). The public key can be a X509 certificate.

At this point no PKCS#8 encryption standard is not considered (sorry, I learnt
it after developing most of my code! ha-ha).
In other words, this code will just accept private key like this:

```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDy0avr8rgm5u7i0UuZURzwJ0rv9TL7vk6Eay5ZJ58rjf2rKU30
Mn6r5zpmHSX/4NvcMAKGO9ZG6oZ4SbhYjE/iJQZWGtGF3InsnI0H4Ly1gCHGBW95
R09Re36WqmoDKryqmsLpOjdd4cqUEvEuctUoOwbi5J7WBw31Mp0rZ/MTcQIDAQAB
AoGAbfDDH7So7mw3ExliWkugh5ey1Uy2xcbXtBr3REStS8IhbaLo+bz3H4w1I9Dk
yKMdyOcv7WkgTsGXGtV+ExGMhN0pcvNfIJfUw67g5SCcrd4JrAZYfNOkgNIbbuaU
0IPXWqeDuFD7ju4j3MYXZzV/lVXzW+fHl22vlfhbi25devECQQD69C+4yazX+/PT
gokJKW6JoUdS4DeYRlrmUolWoWKDgKQLvaqkAjGtxE3IKkXwtxQefbhyho7GX6uz
rUCZnb/NAkEA97OcN5VUC2JmLvfpfUHL0Xf2PzChTL2SwAfZ/ooCXq3ttFA59w0Q
lLsCl/BMve7PhO38i/+gzWkOLuNStMnWNQJAFaloSSIXallUNaip3YGXCghC2NOD
2QARrpnnQvQRRdqfzmejyB5sXVx5flKv0NRsxykA99nHjzYI4yyMS/ZC7QJAZjjj
UTT5GDGlheCdpSmQGYPuRammB2t8sm8LEbaWv8f7fxxUr5Xer+J1cYqjwQZa8brd
LFF0ZRDj34nEygM5uQJBAJn0aw6Eia23uy23Zfrw6ZdZY9/wlC+R+rUJXm7B699k
uA+N1ll6bKMRk7t6T6GOH3fCxmWfZLO4Kei0xZlGNlA=
-----END RSA PRIVATE KEY-----
```

Or, like this:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,8AD7660280DA0D22

gnGId8eLTWW6TdKDw9vg3X1YBXxgYUC/ZDLkEHuaqiyJTBufKMzLDaeJm9HhObGn
Asa99+Lf39imNNNeuo1L+tKYHfGgbCXelEquAshZfuskD1H2yM43nkUCw9s+Zx4Z
6rT+g76c+XEzXes0Timrp/2Y2/k8XgzBPgKAQLPHbkTOSg1fDIrTjnW8YKSVtLAz
/dlPP27oc6a6Dv5ak1QGlr2yx99J7jJ4tXyl1gMovUcMP9PC13lIco8mgsUtphDD
qwNaUwvJ9StFq32E9DvV051ggc2p7vjOdc9EKdy28EG2yA4PzMblsFFnpHd20S10
3uGRxC+7ckxQ/BeD9PLD9V1CDPXOm7qZjMjS9qkYkrSTdlcVaTKIkQHGviyng+wc
uhkWGB4lct1OyArM2PZWh/MQfYv38h1zHiQVbK8raRzeuw5YNwP4yV4j9fA7sEr7
ti9XeKMkxjNKwN3GLIKrDsOoU6VH99X8hPnzxvQmf8dK+X90VR8VsNHLscbvTIj0
5Z1yd7JQw9Id2+V4gbkqdMuDVFwGPgNWjkB7JTSvPTyvceWxo5IqpFAPxKDf7C/7
wiM1Xvq+JKIG2rjRRfugdIBOl0uH3hrKiHt9pAcvZ3jM4ZykxAAaJe4hk9Qi4Vbf
96LuEQBKRnEZUCX01DQocmzB7XTL5FlLypYbqIBHf2o6+TSXVgoAffdZ0cH2TIDj
9CbwIRsEfzJ/ZhT8vQsSod9Xqk7eo1S15A4DzKPulPHzEGK7hkGPn29jYnZ9IeoP
VRjvR/jWxkxupXqthrYDzZjn3FS0WSrgICSFftQZysxbtzd1s3AqlQ==
-----END RSA PRIVATE KEY-----
```

The code will NOT accept this format:

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICxjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIAnq5d3O9Oz4CAggA
MBQGCCqGSIb3DQMHBAgTJyqXpkcePwSCAoB2bxN0MYwqZSp879h1DL2HYff6/RMd
twTonS48+P9Lm8rfBVoV/IlGDyezIplLboUSyjkc9epE46wY8fs9BhEkRZm/v6ib
5wi5PIrfxb95PdzrORw4gIm2H02JCtsAPR9bV8b25/XXOW36GJ3d1DUNf2wHJiFX
3dYTtS5nO8tQPqu9oJynmXFizvAYtNO9XctZtadrRtHkYjMeRzkIQxFAQ44gl7h2
DwSl1S01w0FXEya01En+l9LN6WAon00C8Aa7CStjw5/Yd1sZcoj+HF7vZWfBxGh4
SZg1nSr65W5NYYLuGNYMZpbwFejlrd7i30oReIAnMgqOzazYs9cMsY1P3Rnz9eXi
iGSV1Jop30KwXjOfGnkQ+J1XUE5TlvUFLy5Rw+DWXUpm7gXciU8ihaZ1y05/yeLh
3FyEdYRCztxD7o+V2a/w+62htRgRegg7qJMRPWhj1JXCY6XmjHFoG8EXHp5Dd5rF
/VHcpVvQwlISrbgEdI43R8Ya24lD3F6Lggdlv0okrwM5MoX/jOWJH8cEsTCkD3Pp
1WB30BRSRP/Hyn1+Sz5vnsUWMtQqTx3OZIUz2Dn6XnRbG8ZlFZKzb9Y1Lu2ocEG1
qo3zGIVS9F97trd2anxcZZYwmVKaWx8hUWpvckMmczBut1rybz0UOxSCu23U4tqb
eWwXbTVPHh9wTJJLUwhKA/neq+e5dqYBCEPZgYZfr30/iixC22OZZXhLkcKN1AHa
+nVAqLjB4vj2T807mZwcgJAT1qhKSstw/E8Nch77JU+7i8+w9m8y9X1/mqV0ssRR
hVlxSuGs37evcFDIZ1KYIQWlOlVv4WeN5Xcp3R8EWSbrpMpD/Kmh+xK+
-----END ENCRYPTED PRIVATE KEY-----
```

There are tiny differences

* The first one that starts from "BEGIN RSA PRIVATE KEY" line is
a non-encrypted, PEM encoded RSA private key. Using an ASN.1 decoder,
you'll just see 8 parts of information that are needed for rsa encryption.
* The second one that starts from "BEGIN RSA PRIVATE KEY" line is
an encrypted RSA private key that seems specific to OpenSSL (non-standard one).
OpenSSL natively supports the format while other libraries may not
support it (I suppose so, or, I didn't confirm the assumption well).
* The third one that strats from "BEGIN _ENCRYPTED_ PRIVATE KEY" is
an encrypted RSA private key with PKCS#8 encryption standard (RFC 2898).
OpenSSL supports this format too but with different API set.

You can use a X509 certificate instead of a public key.
You need to prepare X509 cert/key pair to try enc\_dec\_exp.
The certificate is ok with self-signed one.

## rsa_exp

creating an RSA pub/priv key pair (To be documented more)

## sign\_verify\_exp.cpp

signining/verifying a simple text with RSA priv/pub key (To be documented more)

## openssl.php

A simple script using OpenSSL functions in PHP. Very rough. (To be documented more)
