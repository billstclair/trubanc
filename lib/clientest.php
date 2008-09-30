<?PHP

  // clientest.php
  // Test code for the Trubanc client

require_once "client.php";
require_once "fsdb.php";
require_once "ssl.php";

$db = new fsdb("../clientdb");
$ssl = new ssl();
$client = new client($db, $ssl);
$t = $client->t;

/*
echo $client->format_value(10000, 0, 0) . "\n";
echo $client->format_value(10000, 0, 3) . "\n";
echo $client->format_value(12300000, 7, 3) . "\n";
echo $client->format_value("1234567890123", 7, 3) . "\n";
return;
*/

$url = "http://localhost/trubanc";

/*
$server = new serverproxy($url);
echo $server->process("hello") . "\n";
return;
*/

$passphrase3 = "a really lousy passphrase";

$err = $client->newuser($passphrase3, 512);
if ($err) echo "$err\n";

$err = $client->login($passphrase3);
if ($err) die("$err\n");

$id3 = $client->id;
echo "id: $id3\n";

$err = $client->addbank($url);
if ($err) die("$err\n");
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

$passphrase = "Yes another lousy passphrase";

$pk = $ssl->load_private_key($privkey);
openssl_pkey_export($pk, $privkey, $passphrase);
openssl_free_key($pk);
//echo $privkey;

$err = $client->newuser($passphrase, $privkey);
if ($err) echo "$err\n";

$err = $client->login($passphrase);
if ($err) echo "$err\n";

$id = $client->id;
echo "id: $id\n";

$err = $client->addbank($url);
if ($err) echo "$err\n";
else {
  echo "bankid: " . $client->bankid . "\n";
}

// Succeeds this time, because this ID is already registered at the bank.
$err = $client->register('George Jetson');
if ($err) echo "$err\n";

// Adding yourself as a contact won't happen, but it tests the code
$err = $client->addcontact($id, "Me, myself, and I", "A little note to myself");
if ($err) echo "$err\n";

// Another account created by servertest.php
$privkey2 = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAK5kvoBZ9mw6xpt7M0M383q5/mhvzLTr1HUG9kr52aJyaV7OegEQ
ndsN45klFNvzD4slOuh2blg4ca7DuuARuYUCAwEAAQJBAI+aabwrWF268HxrsMSz
OA1hRvscxMZeQ66yMvF+WBYJIE873UDxUUMgvYJ0Dz6kg6u8BFBKcxWBCIP8e2Bi
p2kCIQDaH2fPpAd477Xad+BXUiiSqOgWrEIzMiAkZsE2Q+XgYwIhAMytXoq6eZar
+id+XvcTilxSVagqkC+549Og2HtsDP73AiEAteKEVVBJbt4svY1CxG3dKVaxmd5w
oXJF/TS2HsMFmFMCICZAYGLc5sxZ565p16WlaT5HxOpgygGhZAqxDMRENUmRAiAS
H3CnJ8Ul3VWvyL5hVjFDHYnD6n18+xqsnjeSQ4bRnQ==
-----END RSA PRIVATE KEY-----
";
$pubkey2 = $ssl->privkey_to_pubkey($privkey2);
$id2 = $ssl->pubkey_id($pubkey2);

$err = $client->newuser($passphrase2, $privkey2);
if ($err) echo "$err\n";


$users = array(1 => array('idx' => 1, 'id' => $id, 'name' => 'George Jetson',
                          'passphrase' => $passphrase),
               2 => array('idx' => 2, 'id' => $id2, 'name' => 'Jane Jetson',
                          'passphrase' => $passphrase2),
               3 => array('idx' => 3, 'id' => $id3, 'name' => 'John Doe',
                          'passphrase' => $passphrase3));

// Command loop
while (true) {
  $id = $client->current_user();
  if ($id) {
    foreach ($users as $user) {
      if ($user['id'] == $id) {
        echo "---\n";
        $idx = $user['idx'];
        $name = $user['name'];
        echo "$idx: $name, $id\n";
        break;
      }
    }
  }
  echo "Command (? for help): ";
  $line = fgets(STDIN);
  $tokens = explode(' ', $line);
  foreach ($tokens as $k => $v) $tokens[$k] = trim($v);
  $cmd = $tokens[0];
  if ($cmd == '?') {
    echo "?: help\n" .
      "quit: exit from  the command loop\n" .
      "users: show users\n" .
      "login <user#>: login as <user#>\n" .
      "setbank <bankurl>: set the current bank for the current user\n";
      "assets: list asset types\n" .
      "balance: show balances for current user\n" .
      "spend <user#> <asset#> <amount> [<acct>]: Spend from current user  to <user#>\n" .
      "register <user> <bankurl>: register a new account with the bank\n";
  } elseif ($cmd == 'quit' || $cmd == 'q') {
    exit(0);
  } elseif ($cmd == 'users') {
    foreach($users as $user) {
      echo $user['idx'] . ': ' . $user['name'] . ', ' . $user['id'] . "\n";
    }
  } elseif ($cmd == 'login') {
    if (count($tokens) != 2) {
      echo "Usage is: login <user#>\n";
    } else {
      $idx = $tokens[1];
      $user = $users[$idx];
      if ($user) $client->login($user['passphrase']);
      else echo "Unknown user#: $idx\n";
    }
  }
}

/**** Old code ***
$contacts = $client->getcontacts();
//print_r($contacts);

$err = $client->initbankaccts();
if ($err) echo "$err\n";

$accts = $client->getaccts();
if (is_string($accts)) echo "$accts\n";
else {
  echo "accts: ";
  $first = true;
  foreach ($accts as $acct) {
    if (!$first) echo ", ";
    echo $acct;
  }
  echo "\n";
}

$asset = $client->getasset('7e35436da35cf1731480d0f35f0144b3013ccb35');
if (is_string($asset)) echo "$asset\n";
else print_r($asset);
$asset = $client->getasset('aintnosuchasset');
if (is_string($asset)) echo "$asset\n";
else print_r($asset);

function printbal($bal) {
  global $t;
  $asset = $bal[$t->ASSET];
  $assetname = $bal[$t->ASSETNAME];
  $amount = $bal[$t->AMOUNT];
  $formattedamount = $bal[$t->FORMATTEDAMOUNT];
  echo "  asset:       $asset\n";
  echo "    name:      $assetname\n";
  echo "    amount:    $amount\n";
  echo "    formatted: $formattedamount\n";
}

$balance = $client->getbalance();
if (is_string($balance)) echo "$balance\n";
else {
  foreach ($balance as $acct => $acctbals) {
    echo "Sub-account: $acct\n";
    foreach ($acctbals as $bal) {
      printbal($bal);
    }
  }
}

$balance = $client->getbalance($acct, $bal[$t->ASSET]);
if (is_string($balance)) echo "$balance\n";
else {
  echo "Last balance above:\n";
  printbal($balance);
}

$fees = $client->getfees();
if (is_string($fees)) echo "$fees\n";
else {
  foreach ($fees as $type => $feelist) {
    echo "$type:\n";
    foreach ($feelist as $fee) {
      foreach ($fee as $k => $v) {
        echo "  $k: $v\n";
      }
    }
  }
}
*** End of old code ***/

?>
