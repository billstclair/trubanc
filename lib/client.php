<?PHP

  // client.php
  // A Trubanc client. Talks the protocol of server.php

require_once "tokens.php";
require_once "ssl.php";
require_once "utility.php";
require_once "parser.php";

class client {

  var $db;
  var $ssl;
  var $t;                       // tokens instance
  var $p;                       // parser instance
  var $u;                       // utility instance
  var $pubkeydb;

  // Initialized by login() and newuser()
  var $id;
  var $privkey;

  // initialized by setbank() and addbank()
  var $server;
  var $bankid;

  var $unpack_reqs_key = 'unpack_reqs';

  // $db is an object that does put(key, value), get(key), and dir(key)
  // $ssl is an object that does the protocol of ssl.php
  function client($db, $ssl=false) {
    $this->db = $db;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->pubkeydb = $db->subdir($this->t->PUBKEY);
    $this->parser = new parser($this->pubkeydb, $ssl);
    $this->u = new utility($this->t, $this->parser);
  }

  // API Methods
  // If the return is not specified, it will be false or an error string

  // Create a new user with the given passphrase, error if already there.
  // If $privkey is a string, use that as the private key.
  // If it is an integer, default 3072, create a new private key with that many bits
  // User is logged in when this returns successfully.
  function newuser($passphrase, $privkey=3072) {
    $db = $this->db;
    $t = $this->t;
    $ssl = $this->ssl;

    $hash = $this->passphrasehash($passphrase);
    if ($db->get($t->PRIVKEY . "/$hash")) {
        return "Passphrase already has an associated private key";
    }
    if (!is_string($privkey)) {
      if (!is_numeric($privkey)) return "privkey arg not a string or number";
      $privkey = $ssl->make_privkey($privkey, $passphrase);
    }
    $privkeystr = $privkey;
    $privkey = $ssl->load_private_key($privkey, $passphrase);
    if (!$privkey) return "Could not load private key";
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    $id = $ssl->pubkey_id($pubkey);
    $db->put($t->PRIVKEY . "/$hash", $privkeystr);
    $db->put($this->pubkeykey($id), trim($pubkey) . "\n");

    $this->id = $id;
    $this->privkey = $privkey;
    return false;
  }

  // Log in with the given passphrase. Error if no user associated with passphrase.
  function login($passphrase) {
    $db = $this->db;
    $t = $this->t;
    $ssl = $this->ssl;

    $hash = $this->passphrasehash($passphrase);
    $privkey = $db->GET($t->PRIVKEY . "/$hash");
    if (!$privkey) return "No account for passphrase in database";
    $privkey = $ssl->load_private_key($privkey, $passphrase);
    if (!$privkey) return "Could not load private key";
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    $id = $ssl->pubkey_id($pubkey);

    $this->id = $id;
    $this->privkey = $privkey;
    return false;
  }

  // All the API methods below require the user to be logged in.
  // $id and $privkey must be set.

  // Return all the banks known by the current user:
  // array(array($t->BANKID => $bankid,
  //             $t->NAME => $name,
  //             $t->URL => $url,
  //             $t->PUBKEYSIG => $pubkeysig), ...)
  // $pubkeysig will be blank if the user has no account at the bank.
  function getbanks() {
    $t = $this->t;
    $db = $this->db;
    $id = $this->id;

    $banks = $db->contents($t->ACCOUNT . "/$id");
    $res = array();
    foreach ($banks as $bankid) {
      $bank = array($t->BANKID => $bankid,
                    $t->NAME => $this->bankprop($t->NAME),
                    $t->URL => $this->bankprop($t->URL),
                    $t->PUBKEYSIG => $this->bankprop($t->PUBKEYSIG));
      $res[] = $bank;
    }
    return $res;
  }

  // Add a bank with the given URL to the database.
  // No error, but does nothing, if the bank is already there.
  // Sets the client instance to use this bank until addbank() or setbank()
  // is called to change it.
  function addbank($url) {
    $db = $this->db;
    $t = $this->t;

    // Hash the URL to ensure its name will work as a file name
    $urlhash = sha1($url);
    $urlkey = $t->BANK . '/' . $t->BANKID;
    $bankid = $db->get("$urlkey/$urlhash");
    if ($bankid) return $this->setbank($bankid);

    $u = $this->u;
    $id = $this->id;
    $privkey = $this->privkey;
    $ssl = $this->ssl;
    $parser = $this->parser;

    $server = new serverproxy($url);
    $this->server = $server;
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    $msg = $this->sendmsg($t->BANKID, $pubkey);
    $args = $u->match_message($msg);
    if (is_string($args)) return "Bank's bankid message wrong: $msg";
    $bankid = $args[$t->CUSTOMER];
    if ($args[$t->REQUEST] != $t->REGISTER ||
        $args[$t->BANKID] != $bankid) {
      return "Bank's bankid message wrong: $msg";
    }
    $pubkey = $args[$t->PUBKEY];
    $name = $args[$t->NAME];
    if ($ssl->pubkey_id($pubkey) != $bankid) {
      return "Bank's id doesn't match its public key: $msg";
    }

    // Initialize the bank in the database
    $this->bankid = $bankid;
    $db->put("$urlkey/$urlhash", $bankid);
    $db->put($this->bankkey($t->URL), $url);
    $db->put($this->bankkey($t->NAME), $name);
    $db->put($this->pubkeykey($bankid), trim($pubkey) . "\n");

    // Mark the user as knowing about this bank
    $db->put($this->userbankkey($t->REQ), 1);

    return false;
  }

  // Set the bank to the given id.
  // Sets the client instance to use this bank until addbank() or setbank()
  // is called to change it, by setting $this->bankid and $this->server
  function setbank($bankid) {
    $db = $this->db;
    $t = $this->t;

    $this->bankid = $bankid;

    $url = $this->bankprop($t->URL);
    if (!$url) return "Bank not known: $bankid";
    $server = new serverproxy($url);
    $this->server = $server;

    $req = $this->userbankprop($t->REQ);
    if (!$req) {
      $db->put($this->userbankkey($t->REQ), 1);
    }

    return false;
  }

  // All the API methods below require the user to be logged and the bank to be set.
  // Do this by calling newuser() or login(), and addbank() or setbank().
  // $this->id, $this->privkey, $this->bankid, & $this->server must be set.

  // Register at the current bank.
  // No error if already registered
  function register() {
    $t = $this->t;
    $u = $this->u;
    $db = $this->db;
    $id = $this->id;
    $bankid = $this->bankid;

    // If already registered and we know it, nothing to do
    if ($this->userbankprop($t->PUBKEYSIG)) return false;

    // See if bank already knows us
    $msg = $this->sendmsg($t->ID, $bankid, $id);
    $args = $this->match_bankmsg($msg, $t->ATREGISTER);
    if (is_string($args)) {
      // Bank doesn't know us. Register with bank.
      $msg = $this->sendmsg($t->REGISTER, $bankid, $this->pubkey($id));
      $args = $this->match_bankmsg($msg, $t->ATREGISTER);
    }
    if (is_string($args)) return "Registration failed: $args";

    // Didn't fail. Notice registration here
    $args = $args[$t->MSG];
    if ($args[$t->CUSTOMER] != $id ||
        $args[$t->REQUEST] != $t->REGISTER ||
        $args[$t->BANKID] != $bankid) return "Malformed registration message";
    $pubkey = $args[$t->PUBKEY];
    $keyid = $ssl->pubkey_id($pubkey);
    if ($keyid != $id) return "Server's pubkey wrong";
    $db->put($this->userbankkey($t->PUBKEYSIG), $msg);
    return false;
  }

  // Returns an error string or an array of items of the form:
  //
  //    array($t->ASSET => $assetid,
  //          $t->ASSETNAME => $assetname,
  //          $t->AMOUNT => $amount,
  //          $t->FORMATTEDAMOUNT => $formattedamount,
  //          $t->ACCT => $acct)
  //
  //  where $assetid & $assetname describe the asset, $amount is the
  //  amount, as an integer, $formattedamount is the amoubnt as a
  //  decimal number with the scale and precision applied, and $acct
  //  is the name of the sub-account, default $t->MAIN.
  function getbalance() {
  }

  function spend($toid, $asset, $amount, $acct=false) {
  }

  function transfer($asset, $amount, $fromacct, $toacct) {
  }

  // Returns an error string, or an array of inbox entries, each of which is
  // of one of the form:
  //
  //   array($t->REQUEST => $request
  //         $t->ID => $fromid,
  //         $t->TIME => $time,
  //         $t->ASSET => $assetid,
  //         $t->ASSETNAME => $assetname,
  //         $t->AMOUNT => $amount,
  //         $t->FORMATTEDAMOUNT => $formattedamount,
  //         $t->NOTE => $note)
  //
  // Where $request is $t->SPEND, $t->SPENDACCEPT, or $t->SPENDREJECT,
  // $fromid is the ID of the spender or recipient of your previous spend,
  // $time is the timestamp from the bank on the inbox entry,
  // $assetid & $assetname describe the asset being transferred,
  // $amount is the amount of the asset being transferred, as an integer
  // $formattedamount is the amount as a decimal number with the scale
  // and precision applied,
  // And $NOTE is the note that came back from the recipient with an
  // accept or reject.
  function getinbox() {
  }

  // directions is an array of array($time => $what), where
  // $time is a timestamp in the inbox, and $what is
  // array($t->SPENDACCEPT, $note), array($t->SPENDREJECT, $note), or
  // any non-array to clear an accepted or rejected spend.
  function processinbox($directions) {
  }

  // Returns an error string or the outbox contents as an array of
  // items of the form:
  //
  //   array($t->ID => $recipientid,
  //         $t->ASSET => $assetid,
  //         $t->ASSETNAME => $assetname,
  //         $t->AMOUNT => $amount,
  //         $t->FORMATTEDAMOUNT => formattedamount,
  //         $t->NOTE => $note)
  function getoutbox() {
  }

  // End of API methods

  function passphrasehash($passphrase) {
    return sha1(trim($passphrase));
  }

  // Create a signed customer message.
  // Takes an arbitrary number of args.
  function custmsg() {
    $id = $this->id;
    $u = $this->u;
    $ssl = $this->ssl;
    $privkey = $this->privkey;

    $args = func_get_args();
    $args = array_merge(array($id), $args);
    $msg = $u->makemsg($args);
    $sig = $ssl->sign($msg, $privkey);
    return "$msg:\n$sig";
  }

  // Send a customer message to the server.
  // Takes an arbitrary number of args.
  function sendmsg() {
    $server = $this->server;

    $req = func_get_args();
    $msg = call_user_func_array(array($this, 'custmsg'), $req);
    return $server->process($msg);
  }

  // Unpack a bank message
  // Return a string if parse error or fail from bank
  function match_bankmsg($msg, $request=false) {
    $t = $this->t;
    $u = $this->u;
    $parser = $this->parser;
    $bankid = $this->bankid;

    $reqs = $parser->parse($msg);
    if (!$reqs) return "Parse error: " . $parser->errmsg;

    $req = $reqs[0];
    $args = $u->match_pattern($req);
    if (is_string($args)) return "While matching: $args";
    if ($args[$t->CUSTOMER] != $bankid) return "Return message not from bank";
    if ($args[$t->REQUEST] = $t->FAILED) return $args[$t->ERRMSG];
    if ($request && $args[$t->REQUEST] != $request) {
      return "Wrong return type from bank: $msg";
    }            
    if ($args[$t->MSG]) {
      $msgargs = $u->match_pattern($args[$t->MSG]);
      if (is_string($msgargs)) return "While matching bank-wrapped msg: $msgargs";
      $args[$t->MSG] = $msgargs;
    }
    $args[$this->unpack_reqs_key] = $reqs; // save parse results
    return $args;
  }

  function pubkey($id) {
    $db = $this->pubkeydb;
    return $db->get($id);
  }

  function pubkeykey($id) {
    $t = $this->t;
    return $t->PUBKEY . "/$id";
  }

  function bankkey($prop=false) {
    $t = $this->t;
    $bankid = $this->bankid;

    $key = $t->BANK . "/$bankid";
    return $prop ? "$key/$prop" : $key;
  }

  function bankprop($prop) {
    $db = $this->db;

    return $db->get($this->bankkey($prop));
  }

  function userbankkey($prop=false) {
    $t = $this->t;
    $id = $this->id;
    $bankid = $this->bankid;

    $key = $t->ACCOUNT . "/$id/$bankid";
    return $prop ? "$key/$prop" : $key;
  }

  function userbankprop($prop) {
    $db = $this->db;

    return $db->get($this->userbankkey($prop));
  }
}

class serverproxy {
  var $url;

  function serverproxy($url) {
    if (substr($url,-1) == '/') $url = substr($url, 0, -1);
    $this->url = $url;
  }

  function process($msg) {
    $url = $this->url;
    return file_get_contents("$url/?msg=" . urlencode($msg));
  }
}

?>
