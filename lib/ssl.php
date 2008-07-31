<?PHP

  // SSL key creation, signing, and verification

class ssl {
  // Make a new private key, as a PEM-encoded string
  function make_privkey($bits=2048, $passphrase=false) {
    $privkey = openssl_pkey_new(array('private_key_bits' => $bits));
    if ($passphrase) openssl_pkey_export($privkey, $pkeyout, $passphrase);
    else openssl_pkey_export($privkey, $pkeyout);
    $res = $pkeyout;
    openssl_free_key($privkey);
    return $res;
  }

  // Load a private key into a resource for faster signing
  function load_private_key($privkey, $passphrase=false) {
    if ($passphrase) return openssl_get_privatekey($privkey, $passphrase);
    else return openssl_get_privatekey($privkey);
  }

  // Return the public key for a private key, as a PEM-encoded string
  function privkey_to_pubkey($privkey, $passphrase=false) {
    $free = false;
    if (is_string($privkey)) {
      $privkey = $this->load_private_key($privkey, $passphrase);
      $free = true;
    }
    if (!$privkey) return false;
    $keydata = openssl_pkey_get_details($privkey);
    if ($free) openssl_free_key($privkey);
    return $keydata['key'];
  }

  // Return the ID of a public key, the SHA1 hash of it
  // The key should be a PEM-encoded string, just as returned from
  // privkey_to_pubkey
  function pubkey_id($pubkey) {
    return sha1(trim($pubkey));
  }

  // Sign a message with a private key.
  // Return the signature, base64-encoded
  function sign($msg, $privkey, $passphrase=false) {
    $free = false;
    if (is_string($privkey)) {
      $privkey = $this->load_private_key($privkey, $passphrase);
      $free= true;
    }
    openssl_sign($msg, $signature, $privkey);
    if ($free) openssl_free_key($privkey);
    return chunk_split(base64_encode($signature), 64, "\n");
  }

  // Verify that a message was signed with the private key corresponding
  // to a public key.
  function verify($msg, $signature, $pubkey) {
    return openssl_verify($msg, base64_decode($signature), $pubkey) == 1;
  }
}

// test code
/*
$ssl = new ssl();
$passphrase = false; //"bees knees";
if ($argc > 0) {
  // Works for "php ssl.php file.pem"
  $filename = $argv[$argc-1];
  $privkey = file_get_contents($filename);
 } else $privkey = $ssl->make_privkey(2048, $passphrase);
echo $privkey;
$pubkey = $ssl->privkey_to_pubkey($privkey, $passphrase);
if (!$pubkey) {
  echo "Can't get public key\n";
  return;
}
$hash = $ssl->pubkey_id($pubkey);
echo $pubkey;
echo "ID: $hash\n";

$msg = "Four score and seven years ago, our forefathers set forth...";
$signature = $ssl->sign($msg, $privkey, $passphrase);
echo "Signature size: " . strlen(base64_decode($signature)) . "\n";
echo $signature . "\n";
if ($ssl->verify($msg, $signature, $pubkey)) echo "Verified\n";
else echo "Did not verify\n";
*/
?>
