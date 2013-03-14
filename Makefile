# Copyright 2013 Daisuke Miyakawa
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

TARGETS = dh_exp dh_exp2 rsa_exp enc_dec_exp_cert_file enc_dec_exp_cert_mem enc_dec_exp_rsa_file enc_dec_exp_rsa_mem openssl_php 

all: $(TARGETS)

dh_exp: dh_exp.cpp
	g++ -Wall $^ -lssl -lcrypto -o $@

dh_exp2: dh_exp.cpp
	g++ -Wall $^ -DSIDE2_DEFINED_OUTSIDE -lssl -lcrypto -o $@

enc_dec_exp_cert_file: enc_dec_exp.cpp
	g++ -Wall enc_dec_exp.cpp -DUSE_CERTIFICATE -lssl -lcrypto -o $@

enc_dec_exp_cert_mem: enc_dec_exp.cpp private/memory_key_cert.h 
	g++ -Wall enc_dec_exp.cpp -DUSE_CERTIFICATE -DUSE_MEMORY_KEY -lssl -lcrypto -o $@

enc_dec_exp_rsa_file: enc_dec_exp.cpp
	g++ -Wall enc_dec_exp.cpp -lssl -lcrypto -o $@

enc_dec_exp_rsa_mem: enc_dec_exp.cpp data/memory_key_rsa.h
	g++ -Wall enc_dec_exp.cpp -DUSE_MEMORY_KEY -lssl -lcrypto -o $@

rsa_exp: rsa_exp.cpp
	g++ -Wall $^ -lssl -lcrypto -o $@

openssl_php: openssl.php
	cp openssl.php /var/www/php/
	touch openssl_php

.PHONY: clean
clean:
	rm -f $(TARGETS)
