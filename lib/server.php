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
    $this->parser = new parser($this->pubkeydb);
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

  function outboxhash($id) {
    $bankid = $this->bankid;
    $contents = $this->db->contents($this->outboxkey($id));
    $contents = $this->utility->bignum_sort($contents);
    $tranlist = implode(',', $contents);
    $hash = sha1($tranlist);
    return $this->bankmsg($this->t->OUTBOXHASH, $this->getacctlast($id), $hash);
  }

  function assetID($id, $scale, $precision, $name) {
    return sha1("$id,$scale,$precision,$name");
  }

  // Initialize the database, if it needs initializing
  function setupDB($passphrase) {
    $db = $this->db;
    $ssl = $this->ssl;
    $t = $this->t;
    $bankname = $this->bankname;
    if (!$db->get($t->TIME)) $db->put($t->TIME, '0');
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
      $db->put($t->BANKID, $bankid);
      $regmsg = $this->bankmsg($t->REGISTER, "\n$pubkey", $bankname);
      $db->put($t->PUBKEY . "/$bankid", $pubkey);
      $db->put($t->PUBKEYSIG . "/$bankid", $regmsg);
      $db->put($t->REGFEE, 10);
      $db->put($t->REGFEESIG, $this->bankmsg($t->REGFEE, 0, 0, 10));
      $db->put($t->TRANFEE, 2);
      $db->put($t->TRANFEESIG, $this->bankmsg($t->TRANFEE, 0, 0, 2));
      $token_name = "Asset Tokens";
      if ($this->bankname) $token_name = "$bankname $token_name";
      $tokenid = $this->assetid($bankid, 0, 0, $token_name);
      $this->tokenid = $tokenid;
      $asset = $this->bankmsg($t->ASSET, $tokenid, 0, 0, $token_name);
      $db->put($t->TOKENID, $tokenid);
      $db->put($t->ASSET . "/$tokenid", $asset);
      $accountdir = $t->ACCOUNT . "/$bankid";
      $db->put($this->accttimekey($bankid), 0);
      $db->put($this->acctlastkey($bankid), 0);
      $db->put($this->acctreqkey($bankid), 0);
      $mainkey = $this->acctbalancekey($bankid);
      $db->put("$mainkey/$tokenid", $this->bankmsg($t->BALANCE, 0, $tokenid, -1));
      $db->put($this->outboxhashkey($bankid), $this->outboxhash($bankid));
    } else {
      $privkey = $ssl->load_private_key($db->get($t->PRIVKEY), $passphrase);
      $this->privkey = $privkey;
      $this->bankid = $this->db->get($this->t->BANKID);
      $this->tokenid = $db->get($t->TOKENID);
    }
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

  /*** Request processing ***/
 
  // Lookup a public key
  function do_id($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
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

  /*** End request processing ***/

  function commands() {
    $t = $this->t;
    if (!$this->commands) {
      $names = array($t->ID => array($t->ID),
                     $t->REGISTER => array($t->PUBKEY,$t->NAME=>1),
                     $t->GETREQ => array($t->REQUEST),
                     $t->TIME => array($t->REQUEST),
                     $t->GETFEES => array($t->OPERATION,$t->REQUEST),
                     $t->SPEND => array($t->TIME,$t->ID,$t->ASSET,$t->AMOUNT,$t->NOTE=>1,$t->ACCT=>1),
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
$regfee = $db->get($t->REGFEE);
if (!$db->get($t->PUBKEY, "/$id")) {
  $db->put($server->inboxkey($id) . "/$time",
           $server->signed_spend($time, $id, $tokenid, $regfee * 2, "Gift"));
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
