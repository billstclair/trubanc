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
$passphrase2 = "What do you think I'd use as a passphrase anyway?";
$pk = $ssl->load_private_key($privkey2);
openssl_pkey_export($pk, $privkey2, $passphrase2);
openssl_free_key($pk);
$pubkey2 = $ssl->privkey_to_pubkey($privkey2, $passphrase2);
$id2 = $ssl->pubkey_id($pubkey2);

$err = $client->newuser($passphrase2, $privkey2);
if ($err) echo "$err\n";


$users = array(1 => array('idx' => 1, 'id' => $id, 'name' => 'George Jetson',
                          'passphrase' => $passphrase),
               2 => array('idx' => 2, 'id' => $id2, 'name' => 'Jane Jetson',
                          'passphrase' => $passphrase2),
               3 => array('idx' => 3, 'id' => $id3, 'name' => 'John Doe',
                          'passphrase' => $passphrase3));

$user = $users[2];
$client->login($user['passphrase']);
$banks = $client->getbanks();
$bank = false;
foreach ($banks as $bank) break;
if ($bank) $client->setbank($bank[$t->BANKID]);

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
    $bankid = $client->current_bank();
    $banks = $client->getbanks();
    if ($bankid) {
      foreach ($banks as $bank) {
        if ($bank[$t->BANKID] == $bankid) {
          $bname = $bank[$t->NAME];
          $burl = $bank[$t->URL];
          $bid = $bank[$t->BANKID];
          echo "$bname: $burl $bid\n";
          break;
        }
      }
    }
  }
  if ($client->showprocess) echo "Showing process messages\n";
  echo "Command (? for help): ";
  $line = fgets(STDIN);
  $tokens = explode(' ', $line);
  foreach ($tokens as $k => $v) $tokens[$k] = trim($v);
  $cmd = $tokens[0];
  if ($cmd == '?') {
    echo "?: help\n" .
      "q/quit: exit from  the command loop\n" .
      "show: toggle show process messages\n" .
      "users: show users\n" .
      "login <user#>: login as <user#>\n" .
      "banks: display all banks known to current user\n" .
      "addbank url: Add a bank to the current user\n" .
      "setbank <bank#>: set the current bank for the current user\n" .
      "assets: list asset types\n" .
      "fees: get transaction and registration fees\n" .
      "contacts: list contacts known to the current user\n" .
      "balance: show balances for current user\n" .
      "spend <user#> <asset#> <amount> [<acct>]: Spend from current user to <user#>\n" .
      "outbox: Show outbox\n" .
      "inbox [<time>...]: Show inbox, or process <time> items\n" .
      "register <user> <bankurl>: register a new account with the bank\n" .
      "sessionid: create a new session id and print it\n" .
      "xorcrypt key string: encrypt string with key";
  } elseif ($cmd == 'quit' || $cmd == 'q') {
    exit(0);
  } elseif ($cmd == 'show') {
    $client->showprocess = !$client->showprocess;
  } elseif ($cmd == 'users') {
    foreach($users as $user) {
      echo $user['idx'] . ': ' . $user['name'] . ', ' . $user['id'] . "\n";
    }
  } elseif ($cmd == 'login' || $cmd == 'user') {
    if (count($tokens) != 2) {
      echo "Usage is: login <user#>\n";
    } else {
      $idx = $tokens[1];
      $user = $users[$idx];
      if ($user) {
        $sessionid = $user['sessionid'];
        $err = true;
        if ($sessionid) {
          $err = $client->login_with_sessionid($sessionid);
          if ($err) {
            echo "sessionid login error: $err\n";
          }
        }
        if ($err) {
          $err = $client->login_new_session($user['passphrase']);
          if (!is_string($err)) {
            $sessionid = $err[0];
            $users[$idx]['sessionid'] = $sessionid;
            $err = false;
          }
        }
        if ($err) {
          echo "Login error: $err\n";
        } else {
          $hash = sha1($sessionid);
          echo "sessionid: $sessionid\n" .
               "     hash: $hash\n";
          $banks = $client->getbanks();
          $bank = false;
          foreach ($banks as $bank) break;
          if ($bank) $client->setbank($bank[$t->BANKID]);
        }
      }
      else echo "Unknown user#: $idx\n";
    }
  } elseif ($cmd == 'banks') {
    $i = 1;
    $banks = $client->getbanks();
    foreach ($banks as $bank) {
      $bname = $bank[$t->NAME];
      $burl = $bank[$t->URL];
      $bid = $bank[$t->BANKID];
      echo "$i: $bname $burl $bid\n";
      $i++;
    }
  } elseif ($cmd == 'addbank') {
    if (count($tokens) != 2) {
      echo "Usage is: addbank <url>\n";
    } else {
      $url = $tokens[1];
      $client->addbank($url);
    }
  } elseif ($cmd == 'setbank') {
    if (count($tokens) != 2) {
      echo "Usage is: setbank <bank#>\n";
    } else {
      $idx = $tokens[1];
      $bank = false;
      if ($idx <= count($banks)) {
        $i = $idx;
        foreach ($banks as $bank) {
          if (!--$i) break;
        }
        if ($i > 0) $bank = false;
      }
      if ($bank) $client->setbank($bank[$t->BANKID]);
      else echo "No such bank index: $idx\n";
    }
  } elseif ($cmd == 'assets') {
    $assets = $client->getassets();
    $i = 1;
    foreach ($assets as $asset) {
      $name = $asset[$t->ASSETNAME];
      $assetid = $asset[$t->ASSET];
      $scale = $asset[$t->SCALE];
      $precision = $asset[$t->PRECISION];
      echo "$i: $name $scale/$precision $assetid\n";
      $i++;
    }
  } elseif ($cmd == 'fees') {
    $fees = $client->getfees();
    foreach ($fees as $feetype => $fee) {
      echo "$feetype\n";
      foreach ($fee as $k => $v) {
        echo "  $k: $v\n";
      }
    }
  } elseif ($cmd == 'contacts') {
    $contacts = $client->getcontacts();
    if (is_string($contacts)) {
      echo "$contacts\n";
    } elseif (count($contacts) == 0) {
      echo "No contacts\n";
    }else {
      foreach ($contacts as $contact) {
        echo $contact[$t->NAME] . "\n";
        foreach ($contact as $k => $v) {
          if ($k != $t->NAME) echo "  $k: $v\n";
        }
      }
    }
  } elseif ($cmd == 'balance') {
    $accts = $client->getbalance();
    if (is_string($accts)) echo "Error: $accts\n";
    else {
      foreach ($accts as $acct => $balances) {
        echo "$acct\n";
        foreach ($balances as $balance) {
          $assetname = $balance[$t->ASSETNAME];
          $amt = $balance[$t->FORMATTEDAMOUNT];
          echo "  $assetname: $amt\n";
        }
      }
    }
  } elseif ($cmd == 'spend') {
    $cnt = count($tokens);
    if ($cnt < 4 || $cnt > 5) {
      echo "Usage is: spend <user#> <asset#> <amount> [<acct>]\n";
    } else {
      $useridx = $tokens[1];
      $assetidx = $tokens[2];
      $amt = $tokens[3];
      $acct = false;
      if ($cnt == 5) $acct = $tokens[4];
      $user = $users[$useridx];
      if (!$user) echo "No such user: $useridx\n";
      else {
        $assets = $client->getassets();
        $asset = $assets[$assetidx-1];
        if (!$asset) echo "No such asset: $assetidx\n";
        else {
          $userid = $user['id'];
          $assetid = $asset[$t->ASSET];
          $note = "Spending $amt";
          $err = $client->spend($userid, $assetid, $amt, $acct, $note);
          if ($err) echo "$err\n";
        }
      }
    }
  } elseif ($cmd == 'outbox') {
    $outbox = $client->getoutbox();
    if (is_string($outbox)) echo "$outbox\n";
    elseif (count($outbox) == 0) {
      echo "Outbox is empty\n";
    } else {
      foreach ($outbox as $time => $items) {
        foreach ($items as $item) {
          $request = $item[$t->REQUEST];
          $formattedamount = $item[$t->FORMATTEDAMOUNT];
          $assetname = $item[$t->ASSETNAME];
          if ($request == $t->SPEND) {
            $id = $item[$t->ID];
            $contact = $client->getcontact($id);
            if ($contact) {
              $name = $contact[$t->NICKNAME];
            } else {
              $name = $id;
            }
            echo "$time: spend $formattedamount $assetname to $name\n";
            $note = $item[$t->NOTE];
            if ($note) echo "  note: $note\n";
          } elseif ($request == $t->TRANFEE) {
            echo "  tranfee: $formattedamount $assetname\n";  
          } else {
            echo "Unknown request: \"$request\"\n";
          }
        }
      }
    }
  } elseif ($cmd == 'inbox') {
    $inbox = $client->getinbox();
    if (count($tokens) == 1) {
      foreach ($inbox as $time => $items) {
        echo "$time: ";
        $first = true;
        foreach ($items as $entry) {
          $request = $entry[$t->REQUEST];
          $fromid = $entry[$t->ID];
          $msgtime = $entry[$t->MSGTIME];
          $assetname = $entry[$t->ASSETNAME];
          $formattedamount = $entry[$t->FORMATTEDAMOUNT];
          $note = $entry[$t->NOTE];

          $contact = $client->getcontact($fromid);
          $name = $fromid;
          if ($contact) $name = $contact[$t->NICKNAME];
          if ($first) $first = false;
          else echo "  ";
          if ($request == $t->SPEND || $request == $t->TRANFEE) {
            echo "$formattedamount $assetname from $name\n";
            if ($request == $t->SPEND) {
              echo "  msgtime: $msgtime\n";
            }
          } else {
            // Need to look up outbox entries here
            echo "$request from $name\n";
          }
          if ($note) echo "  note: $note\n";
        }
      }
      if (count($inbox) == 0) echo "Inbox is empty\n";
    } else {
      // processinbox
      // Rest of line is times
      $directions = array();
      for ($i=1; $i<count($tokens); $i++) {
        $time = $tokens[$i];
        $in = $inbox[$time];
        if (!$in) {
          echo "Not a timestamp in the inbox: $time\n";
          $directions = false;
          break;
        }
        $dir = array();
        $dir[$t->TIME] = $time;
        $in = $in[0];
        if ($in[$t->REQUEST] == $t->SPEND) {
          echo "$time: Accept or Reject? ";
          $line = trim(fgets(STDIN));
          if ($line == 'a') {
            $dir[$t->REQUEST] = $t->SPENDACCEPT;
            echo "Account (main): ";
            $acct = trim(fgets(STDIN));
            if (!$acct) $acct = $t->MAIN;
            $dir[$t->ACCT] = $acct;
          }
          elseif ($line == 'r') $dir[$t->REQUEST] = $t->SPENDREJECT;
          else {
            echo "Must enter 'a' or 'r'\n";
            $directions = false;
            break;
          }
          echo "Note: ";
          $note = trim(fgets(STDIN));
          if ($note) $dir[$t->NOTE] = $note;
        }
        $directions[] = $dir;
      }
      if ($directions) {
        $res = $client->processinbox($directions);
        if ($res) echo "Error: $res\n";
        else echo "Inbox processeed successfully.\n";
      }
    }
  } elseif ($cmd == 'sessionid') {
    $sessionid = $client->newsessionid();
    echo "Session ID: $sessionid\n";
  } elseif ($cmd == 'xorcrypt') {
    if (count($tokens) != 3) {
      echo "Usage is: xorcrypt key string\n";
    } else {
      $key = $tokens[1];
      $string = $tokens[2];
      $res = $client->xorcrypt($key, $string);
      echo "xorcrypt('$key', '$string') = '$res'\n";
      $string = $client->xorcrypt($key, $res);
      echo "xorcrypt('$key', '$res') = '$string'\n";
    }
  } else {
    echo "Unknown command: $cmd\n";
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

// Copyright 2008 Bill St. Clair
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions
// and limitations under the License.

?>
