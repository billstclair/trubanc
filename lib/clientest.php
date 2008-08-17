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

echo "id: '" . $client->id . "'\n";

$err = $client->addbank($url);
if ($err) echo "$err\n";
else {
  echo "bankid: " . $client->bankid . "\n";
  echo "server:"; print_r($client->server);
}

?>
