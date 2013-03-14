<html>
<head><title>OpenSSL</title></head>
<body>
<h1>OpenSSL + PHP Test</h1>
<pre>
<?php

$priv_key = openssl_pkey_new();

// $password = 'eafgq8ee6v3tpcr35ti4dldowteqwwpk';
$password = null;
openssl_pkey_export($priv_key, $priv_key_pem, $password);
print $priv_key_pem;

/*$ar = explode("\n", $priv_key_pem);
array_pop($ar); // delete "-----BEGIN ... -----" line
array_shift($ar); // delete  "-----END ... -----" line
implode($ar);*/

$ret = openssl_pkey_get_details($priv_key);
if (is_array($ret) && in_array('key', $ret)) {
    $pub_key_pem = $ret['key'];
}

if (isset($pub_key_pem)) {
    print $pub_key_pem;
} else {
    print "no public key found: " . $ret;
}

print "\n";

$input = "hogehoge";

// $input = "7a28905fb0f0943c2062e5b54375ee6d4a7e07c727f"
//    . "a85d04d7373a2fae9e74bfe96ce2e930465a9e16a10"
//    . "d04bec4773d4d57ec2ce15f842b5839";

//    "d04bec4773d4d57ec2ce15f842b5839652bf71bc55";
// $input = "7a28905fb0f0943c2062e5b54375ee6d4a7e07c727fa85d04d7373a2fae9e74bfe96ce2e930465a9e16a10d04bec4773d4d57ec2ce15f842bheuo";

// Note: openssl_public_encrypt() fails
// when string with more than 117-chars being provided.
print "input length: " . strlen($input) . "\n";
if (strlen($input) > 117) {
    print "Warning: input is too long. encryption may fail..";
}

if (openssl_public_encrypt($input, $encrypted, $pub_key_pem)) {
    print "Encrypted by pub_key: \"" . base64_encode($encrypted) . "\"\n";
    $priv_key2 = openssl_get_privatekey($priv_key_pem, $password);
    if (openssl_private_decrypt($encrypted, $decrypted, $priv_key2)) {
        print "Decrypted by priv_key: \"" . $decrypted . "\"\n";
    } else {
        print "Decryption by priv_key failed.\n";
    }
} else {
    print "Encription by pub_key failed.\n";
}

print "\n";

$priv_key2 = openssl_get_privatekey($priv_key_pem, $password);
if (openssl_private_encrypt($input, $encrypted, $priv_key2)) {
    print "Encrypted by priv_key: \"" . base64_encode($encrypted) . "\"\n";
    if (openssl_public_decrypt($encrypted, $decrypted, $pub_key_pem)) {
        print "Decrypted by pub_key: \"" . $decrypted . "\"\n";
    } else {
        print "Decryption by pub_key failed.\n";
    }
} else {
    print "Encryption by priv_key_failed\n";
}

?>

</pre>
<hr>
Done<br />
</body>
</html>
