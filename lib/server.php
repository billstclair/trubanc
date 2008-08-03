<?PHP

  // server.php
  // Implement the server protocol

require_once "tokens.php";
require_once "ssl.php";
require_once "utility.php";
require_once "parser.php";

class server {

  var $db;
  var $ssl;
  var $t;
  var $parser;
  var $utility;
  var $pubkeydb;
  var $bankname;
  var $regfee;
  var $tranfee;

  var $privkey;
  var $bankid;

  // $db is an object that does put(key, value), get(key), and dir(key)
  // $ssl is an object that does the protocol of ssl.php
  // $bankname is used to initialize the bank name in a new database. Ignored otherwise.
  function server($db, $ssl=false, $passphrase=false, $bankname='') {
    $this->db = $db;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->pubkeydb = $db->subdir($this->t->PUBKEY);
    $this->parser = new parser($this->pubkeydb, $ssl);
    $this->utility = new utility();
    $this->bankname = $bankname;
    $this->setupDB($passphrase);
  }

  function gettime() {
    $db = $this->db;
    $t = $this->t;
    $lock = $db->lock($t->TIME);
    $res = $db->get($t->TIME) + 1;
    $db->put($t->TIME, $res);
    $db->unlock($lock);
    return $res;
  }

  function getacctlast($id) {
    return $this->db->get($this->acctlastkey($id));
  }

  function getacctreq($id) {
    return $this->db->get($this->acctreqkey($id));
  }

  function accountdir($id) {
    return $this->t->ACCOUNT . "/$id" . '/';
  }

  function accttimekey($id) {
    return $this->accountdir($id) . $this->t->TIME;
  }

  function acctlastkey($id) {
    return $this->accountdir($id) . $this->t->LAST;
  }

  function acctreqkey($id) {
    return $this->accountdir($id) . $this->t->REQ;
  }

  function balancekey($id) {
    return $this->accountdir($id) . $this->t->BALANCE;
  }

  function acctbalancekey($id, $acct='main') {
    return $this->balancekey($id) . "/$acct";
  }

  function outboxkey($id) {
    return $this->accountdir($id) . $this->t->OUTBOX;
  }

  function outboxhashkey($id) {
    return $this->accountdir($id) . $this->t->OUTBOXHASH;
  }

  function inboxkey($id) {
    return $this->accountdir($id) . $this->t->INBOX;
  }

  function outboxhash($id, $transtime, $newitem=false) {
    $parser = $this->parser;
    $db = $this->db;
    $dir = $this->outboxkey($id);
    $contents = $this->db->contents($this->outboxkey($id));
    if ($newitem) $contents[] = $transtime;
    $contents = $this->utility->bignum_sort($contents);
    $unhashed = '';
    foreach ($contents as $time) {
      if (bccomp($time, $transtime) <= 0) {
        if ($time == $transtime) $item = $newtime;
        else $item = $db->get("$dir/$time");
        $entry = $parser->unsigned_message($item);
        if ($unhashed != '') $unhashed .= '.';
        $unhashed .= $entry;
      }
    }
    $tranlist = implode(',', $contents);
    return sha1($tranlist);
  }

  function outboxhashmsg($id, $transtime) {
    return $this->bankmsg($this->t->OUTBOXHASH, $this->getacctlast($id),
                          $this->outboxhash($id, $transtime));
  }

  function assetID($id, $scale, $precision, $name) {
    return sha1("$id,$scale,$precision,$name");
  }

  function is_asset($assetid) {
    return $this->db->get($this->t->ASSET . "/$assetid");
  }

  function lookup_asset($assetid) {
    $asset = is_assset($assetid);
    return $this->parser->parse($asset);
  }

  function lookup_asset_name($assetid) {
    $assetreq = $this->lookup_asset($assetid);
    return $assetreq[5];
  }

  function lookup_tranfee() {
    return $this->db->get($this->t->TRANFEE);
  }

  function is_alphanumeric($char) {
    $ord = ord($char);
    return ($ord >= ord('0') && $ord <= ord('9')) ||
      ($ord >= ord('A') && $ord <= ord('Z')) ||
      ($ord >= ord('a') && $ord <= ord('z'));
  }

  function is_acct_name($acct) {
    for ($i=0; $i<strlen($acct); $i++) {
      if (!is_alphanumeric(substr($acct, $i, 1))) return false;
    }
    return true;
  }

  // Initialize the database, if it needs initializing
  function setupDB($passphrase) {
    $db = $this->db;
    $ssl = $this->ssl;
    $t = $this->t;
    $bankname = $this->bankname;
    if (!$db->get($t->PRIVKEY)) {
      // http://www.rsa.com/rsalabs/node.asp?id=2004 recommends that 3072-bit
      // RSA keys are equivalent to 128-bit symmetric keys, and they should be
      // secure past 2031.
      $privkey = $ssl->make_privkey(3072, $passphrase);
      $db->put($t->PRIVKEY, $privkey);
      $privkey = $ssl->load_private_key($privkey, $passphrase);
      $this->privkey = $privkey;
      $pubkey = $ssl->privkey_to_pubkey($privkey);
      $bankid = $ssl->pubkey_id($pubkey);
      $this->bankid = $bankid;
      $db->put($t->TIME, $this->bankmsg($t->TIME, '0'));
      $db->put($t->BANKID, $this->bankmsg($t->BANKID, $bankid));
      $regmsg = $this->bankmsg($t->REGISTER, "\n$pubkey", $bankname);
      $db->put($t->PUBKEY . "/$bankid", $pubkey);
      $db->put($t->PUBKEYSIG . "/$bankid", $regmsg);
      $token_name = "Asset Tokens";
      if ($this->bankname) $token_name = "$bankname $token_name";
      $tokenid = $this->assetid($bankid, 0, 0, $token_name);
      $this->tokenid = $tokenid;
      $asset = $this->bankmsg($t->ASSET, $tokenid, 0, 0, $token_name);
      $db->put($t->TOKENID, $this->bankmsg($t->TOKENID, $tokenid));
      $db->put($t->ASSET . "/$tokenid", $this->bankmsg($t->ATASSET, $asset));
      $this->regfee = 10;
      $db->put($t->REGFEE, $this->bankmsg($t->REGFEE, 0, $tokenid, $this->regfee));
      $this->tranfee = 2;
      $db->put($t->TRANFEE, $this->bankmsg($t->TRANFEE, 0, $tokenid, $this->tranfee));
      $accountdir = $t->ACCOUNT . "/$bankid";
      $db->put($this->accttimekey($bankid), 0);
      $db->put($this->acctlastkey($bankid), 0);
      $db->put($this->acctreqkey($bankid), 0);
      $mainkey = $this->acctbalancekey($bankid);
      $db->put("$mainkey/$tokenid",
               $this->bankmsg($t->ATBALANCE,$this->bankmsg($t->BALANCE, 0, $tokenid, -1)));
      $db->put($this->outboxhashkey($bankid),
               $this->bankmsg($t->ATOUTBOXHASH, $this->outboxhashmsg($bankid, 0)));
    } else {
      $privkey = $ssl->load_private_key($db->get($t->PRIVKEY), $passphrase);
      $this->privkey = $privkey;
      $this->bankid = $this->get_signed_db_item($db, $bankid, $t->BANKID);
      $this->regfee = $this->get_signed_db_item($db, $bankid, $t->REGFEE);
      $this->tranfee = $this->get_signed_db_item($db, $bankid, $t->TRANFEE);
      $msg = $db->get($t->TOKENID);
      $this->tokenid = $req[2];
    }
  }

  // Get a signed item from the database
  function get_signed_db_item($db, $bankid, $key) {
    $msg = $this->db->get($key);
    if (!$msg) die("No value for /$key");
    $req = $parser->parse($msg);
    if (!$req) die("While parsing $msg: " . $parser->errmsg);
    if ($req[0] != $bankid) die("Wrong bankid in $msg");
    if ($req[1] != $key) die("Key should be '$key' in $msg");
    return $req[2];
  }

  // Bank sign a message
  function banksign($msg) {
    $sig = $this->ssl->sign($msg, $this->privkey);
    return "$msg:\n$sig";
  }

  // Make a bank signed message from $array
  // Takes as many args as you care to pass.
  function bankmsg() {
    $args = func_get_args();
    $msg = array_merge(array($this->bankid), $args);
    return $this->banksign($this->utility->makemsg($msg));
  }

  // Takes as many args as you care to pass
  function failmsg() {
    $args = func_get_args();
    $msg = array_merge(array($this->bankid, $this->t->FAILED), $args);
    return $this->banksign($this->utility->makemsg($msg));
  }

  function scaninbox($id) {
    $db = $this->db;
    $inboxkey = $this->inboxkey($id);
    $times = $db->contents($inboxkey);
    $res = array();
    foreach ($times as $time) {
      $res[] = $db->get("$inboxkey/$time");
    }
    return $res;
  }

  function signed_balance($time, $asset, $amount, $acct=false) {
    if ($acct) {
      return $this->bankmsg($this->t->BALANCE, $time, $asset, $amount, $acct);
    } else {
      return $this->bankmsg($this->t->BALANCE, $time, $asset, $amount);
    }
  }

  function signed_spend($time, $id, $assetid, $amount, $note=false, $acct=false) {
    if ($note && $acct) {
      return $this->bankmsg($this->t->SPEND, $time, $id, $assetid, $amount, $note, $acct);
    } elseif ($note) {
      return $this->bankmsg($this->t->SPEND, $time, $id, $assetid, $amount, $note);
    } elseif ($acct) {
      return $this->bankmsg($this->t->SPEND, $time, $id, $assetid, $amount, "acct=$acct");
    } else return $this->bankmsg($this->t->SPEND, $time, $id, $assetid, $amount);
  }

  function enq_time($id) {
    $db = $this->db;
    $time = $this->gettime();
    $key = $this->accttimekey($id);
    $lock = $db->lock($key);
    $q = $db->get($key);
    if (!$q) $q = $time;
    else $q .= ",$time";
    $db->put($q);
    $db->unlock($lock);
    return $q;
  }

  function deq_time($id) {
    $db = $this->db;
    $key = $this->accttimekey($id);
    $lock = $db->lock($key);
    $q = $db->get($key);
    if (!$q) return false;
    $pos = strpos(',', $q);
    if (!$pos) {
      $time = $q;
      $q = 0; // don't want to delete the file, so store 0 instead of ''
    } else {
      $time = strpos($q, 0, $pos);
      $q = strpos($q, $pos+1);
    }
    $db->put($key, $q);
    $db->put($this->acctlastkey($id), $time);
    $db->unlock($lock);
    return $time;
  }

  /*** Request processing ***/
 
  // Lookup a public key
  function do_id($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    // $t->ID => array($t->ID)
    $customer = $args[$t->CUSTOMER];
    $id = $args[$t->ID];
    if ($id == '0') $id = $this->bankid;
    $key = $db->get($t->PUBKEYSIG . "/$id");
    if ($key) return $key;
    else return $this->failmsg($msg, 'No such public key');
  }

  // Register a new account
  function do_register($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    // $t->REGISTER => array($t->PUBKEY,$t->NAME=>1)
    $id = $args[$t->CUSTOMER];
    $pubkey = $args[$t->PUBKEY];
    if ($this->pubkeydb->get($id)) {
      return $this->failmsg($msg, "Already registered");
    }
    if ($this->ssl->pubkey_id($pubkey) != $id) {
      return $this->failmsg($msg, "Pubkey doesn't match ID");
    }
    if ($this->ssl->pubkey_bits($pubkey) > 4096) {
      return $this->failmsg($msg, "Key sizes larger than 4096 not allowed");
    }
    $regfee = $db->get($t->REGFEE);
    $tokenid = $this->tokenid;
    $success = false;
    if ($regfee > 0) {
      $inbox = $this->scaninbox($id);
      foreach ($inbox as $inmsg) {
        $parse = $this->parser->parse($inmsg);
        if (!$parse) {
          return $this->failmsg("Error parsing inbox: " . $parser->errmsg . ":\n$inmsg");
        }
        $parse = $parse[0];
        if ($parse[1] == $t->SPEND) {
          $asset = $parse[4];
          $amount = $parse[5];
          if ($asset == $tokenid && $amount >= $regfee) {
            $success = true;
            break;
          }
        }
      }
      if (!$success) {
        return $this->failmsg($msg, "Insufficient usage tokens for registration fee");
      }
    }
    $bankid = $this->bankid;
    $db->put($t->PUBKEY . "/$id", $pubkey);
    $db->put($t->PUBKEYSIG . "/$id", $msg);
    $time = $this->gettime();
    if ($regfee != 0) {
      $db->put($this->inboxkey($id) . "/$time", $this->signed_spend($time, $id, $tokenid, -$regfee, "Registration fee"));
    }
    $db->put($this->accttimekey($id), 0);
    $db->put($this->acctlastkey($id), $time);
    $db->put($this->acctreqkey($id), 0);
    return $db->get($t->PUBKEYSIG . "/$bankid");
  }

  // Process a spend
  function do_spend($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    // $t->SPEND => array($t->TIME,$t->ID,$t->ASSET,$t->AMOUNT,$t->NOTE=>1),
    $id = $args[$t->CUSTOMER];
    $time = $args[$t->TIME];
    $id2 = $args[$t->ID];
    $assetid = $args[$t->ASSET];
    $amount = $args[$t->AMOUNT];
    $note = $args[$t->NOTE];

    // Burn the transaction, even if balances don't match.
    $accttime = $this->deq_time($id);
    if (!$accttime) return $this->failmsg($msg, "No timestamp enqueued");
    if ($accttime != $time) return $this->failmsg($msg, "Timestamp mismatch");

    if (!$this->is_asset($assetid)) {
      return $this->failmsg($msg, "Unknown asset id: $assetid");
    }
    if (!is_numeric($amount)) {
      return $this->failmsg($msg, "Not a number: $amount");
    }

    $tokens = 0;
    $tokenid = $this->tokenid;
    if ($id != $id2) {
      // Spends to yourself are free
      $tokens = $this->lookup_tranfee();
    }

    $bals = array($tokenid => -$tokens,
                  $assetid => -$amount);
    $acctbals = array();
    $newbalcnt = 0;             // number of new balance slots needed. Each costs a token

    $outboxhash = false;
    $first = true;
    foreach ($reqs as $req) {
      if ($first) next;
      else $first = false;
      $reqargs = $this->match_pattern($msg, $req);
      if (is_string($req_args)) return $reqargs; // match error
      $reqid = $reqargs[$t->CUSTOMER];
      $reqreq = $reqargs[$t->REQ];
      $reqtime = $reqargs[$t->TIME];
      if ($reqtime != $time) return $this->failmsg($msg, "Timestamp mismatch");
      if ($reqid != $id) return $this->failmsg($msg, "ID mismatch");
      if ($reqreq == $t->BALANCE) {
        $balasset = $t->ASSET;
        $balamount = $t->AMOUNT;
        if ($balamount < 0) return $this->failmsg($msg, "Balance may not be negative");
        $acct = $t->ACCT || $t->MAIN;
        if (!$this->is_asset($balasset)) {
          return $this->failmsg($msg, "Unknown asset id: $balasset");
        }
        if (!is_numeric($balamount)) {
          return $this->failmsg($msg, "Not a number: $balamount");
        }
        if (!is_acct_name($acct)) {
          return $this->failmsg($msg, "Acct may contain only letters and digits: $acct");
        }
        $acctbals[$acct][$balasset] += $balamount;
        $bals[$balasset] += $balamount;
        $acctmsg = $db->get($this->acctbalancekey($id, $acct));
        if (!$acctmsg) $newbalcnt++;
        else {
          $acctreq = $parser->parse($acctmsg);
          if ($acctreq) $acctargs = $this->match_pattern($acctmsg, $acctreq);
          else $acctargs = false;
          if (!$acctargs || $acctargs[$t->ASSET] != $balasset) {
            // This really needs to notify the bank owner, somehow. We're in deep shit.
            $name = $this->lookup_asset_name($balasset);
            return $this->failmsg($msg, "Bank entry corrupted for acct: $acct, asset: $name ($balasset)");
          }
          $bals[$balasset] -= $acctargs[$t->AMOUNT];
        }
      } elseif ($reqreq == $t->OUTBOXHASH) {
        if ($outboxhash) {
          return $this->failmsg($msg, $t->OUTBOXHASH . " appeared multiple times");
        }
        $outboxhash = $req;
        $hash = $reqargs[$t->HASH];
      } else {
        return $this->failmsg($msg, "$reqreq not valid for spend. Only " . $t->BALANCE .
                              "and " . $t->OUTBOXHASH);
      }
    }

    // Charge a token for each new balance file
    $bals[$tokenid] -= $newbalcnt;

    $errmsg = "";
    $first = true;
    foreach ($bals as $balasset => $balamount) {
      if ($balamount != 0) {
        $name = $this->lookup_asset_name($balasset);
        if (!$first) $errmsg .= ', ';
        $first = false;
        $errmsg .= "$name: $balamount";
      }
    }
    if ($errmsg != '') return $this->failmsg($msg, "Balance discrepanies: $errmsg");

    if ($this->outboxhash($id, $outboxhash) != $hash) {
      return $this->failmsg($msg, $t->OUTBOXHASH . ' mismatch');
    }

    // All's well with the world. Commit this baby.
    $spendmsg = $parser->first_message($msg);
    $inbox_item = $this->bankmsg($this->INBOX, $this->gettime(), $spendmsg);
    
    // Grab lock

    // Append spend to outbox

    // Update balances

    // Append spend to recipient's inbox

    // Release lock

    // Create return message
  }

  /*** End request processing ***/

  // Patterns for non-request data
  function patterns() {
    $t = $this->t;
    if (!$this->patterns) {
      $patterns = array($t->BALANCE => array($t->TIME, $t->ASSET, $t->AMOUNT, $t->ACCT=>1),
                        $t->OUTBOXHASH => array($t->TIME, $t->HASH));
      $this->patterns = $patterns;
    }
    return $this->patterns;
  }

  function match_pattern($msg, $req) {
    $pattern = $this->patterns[$req[1]];
    if ($pattern) return $this->failmsg($msg, "Unknown request: " . $req[1]);
    $pattern = array_merge(array($t->CUSTOMER,$t->REQ), $pattern);
    $args = $this->parser->matchargs($req, $pattern);
    if (!$args) {
      return $this->failmsg($msg,
                            "Request doesn't match pattern: " .
                            $parser->formatpattern($pattern));
    }
    return $args;
  }

  function commands() {
    $t = $this->t;
    if (!$this->commands) {
      $names = array($t->ID => array($t->ID),
                     $t->REGISTER => array($t->PUBKEY,$t->NAME=>1),
                     $t->GETREQ => array($t->REQUEST),
                     $t->TIME => array($t->REQUEST),
                     $t->GETFEES => array($t->OPERATION,$t->REQUEST),
                     $t->SPEND => array($t->TIME,$t->ID,$t->ASSET,$t->AMOUNT,$t->NOTE=>1),
                     $t->INBOX => array($t->REQUEST),
                     $t->PROCESSINBOX => array($t->TIMELIST),
                     $t->GETASSET => array($t->ASSET,$t->REQUEST),
                     $t->ASSET => array($t->ASSET,$t->SCALE,$t->PRECISION,$t->ASSETNAME),
                     $t->GETOUTBOX => array($t->REQUEST),
                     $t->GETBALANCE => array($t->REQUEST,$t->ACCT));
      $commands = array();
      foreach($names as $name => $pattern) {
        $commands[$name] = array("do_$name", $pattern);
      }
      $this->commands = $commands;
    }
    return $this->commands;
  }

  // Process a message and return the response
  // This is usually all you'll call from outside
  function process($msg) {
    $parser = $this->parser;
    $t = $this->t;
    $parses = $parser->parse($msg);
    if (!$parses) {
      return $this->failmsg($msg, $parser->errmsg);
    }
    $req = $parses[0][1];
    $commands = $this->commands();
    $method_pattern = $commands[$req];
    if (!$method_pattern) {
      return $this->failmsg($msg, "Unknown request: $req");
    }
    $method = $method_pattern[0];
    $pattern = array_merge(array($t->CUSTOMER,$t->REQ), $method_pattern[1]);
    $args = $this->parser->matchargs($parses[0], $pattern);
    if (!$args) {
      return $this->failmsg($msg,
                            "Request doesn't match pattern: " .
                            $parser->formatpattern($pattern));
    }
    return $this->$method($args, $parses, $msg);
  }

}

// Test code

require_once "fsdb.php";
require_once "ssl.php";

$db = new fsdb("../trubancdb");
$ssl = new ssl();
$server = new server($db, $ssl, false, 'Trubanc');

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
$pubkey = $ssl->privkey_to_pubkey($privkey);
$id = $ssl->pubkey_id($pubkey);

function custmsg() {
  global $id, $server, $ssl, $privkey;
  $args = func_get_args();
  $args = array_merge(array($id), $args);
  $msg = $server->utility->makemsg($args);
  $sig = $ssl->sign($msg, $privkey);
  return "$msg:\n$sig";
}

function process($msg) {
  global $server;

  echo "\n=== Msg ===\n$msg\n";
  echo "=== Response ===\n";
  echo $server->process($msg);
}

// Fake a spend of tokens to the customer
$time = $server->gettime();
$tokenid = $server->tokenid;
$t = $server->t;
$regfee = $server->regfee;
if (!$db->get($t->PUBKEY, "/$id")) {
  $db->put($server->inboxkey($id) . "/$time",
           $server->bankmsg($t->INBOX,
                            $server->signed_spend($time, $id, $tokenid, $regfee * 2, "Gift")));
}

echo process(custmsg("register",$pubkey,"George Jetson"));
echo process(custmsg('id',0));
echo process(custmsg('id',$id));

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
