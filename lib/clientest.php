<?PHP

  // clientest.php
  // Test code for the Trubanc client

require_once "client.php";
require_once "fsdb.php";
require_once "ssl.php";

$db = new fsdb("../clientdb");
$ssl = new ssl();
$client = new client($db, $ssl);

$url = "http://localhost/trubanc";

/*
$server = new serverproxy($url);
echo $server->process("hello") . "\n";
return;
*/

$passphrase = "a really lousy passphrase";

$err = $client->newuser($passphrase, 512);
if ($err) echo "$err\n";

$err = $client->login($passphrase);
if ($err) echo "$err\n";

$id = $client->id;
echo "id: $id\n";

$err = $client->addbank($url);
if ($err) echo "$err\n";
else {
  echo "bankid: " . $client->bankid . "\n";
  //echo "server:"; print_r($client->server);
}

$banks = $client->getbanks();
if (is_string($banks)) echo "getbanks error: $banks\n";
//print_r($banks);

// This fails because the customer has no tokens.
$err = $client->register('John Doe');
if ($err) echo "$err\n";

// This is an example key from servertest.php.
// I'm using it because that ID is in my server testing database.
$privkey = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMwfcmkk2coTuYAEbdZ5iXggObNPzbSiDnVtndZFe4/4Xg0IQPfp
Q04OkhWIftMy1OjFhGlBzzNzdW98KYwKMgsCAwEAAQJASAgk4LPPYz84q9NkS1ZS
S6Dbm8pipga2IXxQQaf9ZZ02vWpJR0tTlxq36Zl5P+aAbMck0AvHLgiawx0qWxRz
2QIhAPwyHhCeoZ972KcRi4AIVsWtkGfQsVpVbBOzuFmtAdU9AiEAzzOwvhW6az25
MyxD5VnbEhswT+lDnGAx/WSsHlPqaOcCIQCM0ac7/Heex9Z3ozJTsVRSWNHTRhJh
sGUCs01ytUnauQIgeZrNrRHVgeEM04K0KmPtFZhNZ2jwnFM8o4m1FmuLlJsCIQDc
9tCyRjE3Zj0tXfZL2n6DGeyAc0OsfdQn6V0tFPf6hg==
-----END RSA PRIVATE KEY-----
";

$passphrase2 = "Yes another lousy passphrase";

$pk = $ssl->load_private_key($privkey);
openssl_pkey_export($pk, $privkey, $passphrase2);
openssl_free_key($pk);
//echo $privkey;

$err = $client->newuser($passphrase2, $privkey);
if ($err) echo "$err\n";

$err = $client->login($passphrase2);
if ($err) echo "$err\n";

$id = $client->id;
echo "id: $id\n";

$err = $client->addbank($url);
if ($err) echo "$err\n";
else {
  echo "bankid: " . $client->bankid . "\n";
}

// This fails because the customer has no tokens.
$err = $client->register('George Jetson');
if ($err) echo "$err\n";

?>
