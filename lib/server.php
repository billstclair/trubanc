<?PHP

  // server.php
  // Implement the server protocol

require_once "tokens.php";
require_once "utility.php";
require_once "parser.php";

class server {

  var $db;
  var $ssl;
  var $t;
  var $parser;
  var $utility;
  var $bankname;

  var $privkey;
  var $bankid;

  // $db is an object that does put(key, value), get(key), and dir(key)
  // $ssl is an object that does the protocol of ssl.php
  // $bankname is used to initialize the bank name in a new database. Ignored otherwise.
  function server($db, $ssl, $passphrase=false, $bankname='') {
    $this->db = $db;
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->parser = new parser($db->subdir($this->t->PUBKEY));
    $this->utility = new utility();
    $this->bankname = $bankname;
    $this->setupDB($passphrase);
  }

  function getsequence() {
    $db = $this->db;
    $t = $this->t;
    $lock = $db->lock($t->SEQUENCE);
    $res = $db->get($t->SEQUENCE) + 1;
    $db->put($t->SEQUENCE, $res);
    $db->unlock($lock);
    return $res;
  }

  function getacctlast($id) {
    return $this->db->get($this->acctlastkey($id));
  }

  function getacctlastrequest($id) {
    return $this->db->get($this->acctlastrequestkey($id));
  }

  function accountdir($id) {
    return $this->t->ACCOUNT . "/$id" . '/';
  }

  function acctlastkey($id) {
    return $this->accountdir($id) . $this->t->LAST;
  }

  function acctlastrequestkey($id) {
    return $this->accountdir($id) . $this->t->LASTREQUEST;
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

  // Initialize the database, if it needs initializing
  function setupDB($passphrase) {
    $db = $this->db;
    $ssl = $this->ssl;
    $t = $this->t;
    if (!$db->get($t->SEQUENCE)) $db->put($t->SEQUENCE, '0');
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
      $db->put($t->PRIVKEYID, $bankid);
      $idmsg = $this->bankmsg($t->PUBKEY, $pubkey, $this->bankname);
      $db->put($t->PUBKEY . "/$bankid", $pubkey);
      $db->put($t->PUBKEYSIG . "/$bankid", $idmsg);
      $db->put($t->REGFEE, 10);
      $db->put($t->REGFEESIG, $this->bankmsg($t->REGFEE, $this->getsequence(), 0, 10));
      $db->put($t->TRANFEE, 2);
      $db->put($t->TRANFEESIG, $this->bankmsg($t->TRANFEE, $this->getsequence(), 0, 2));
      $assetname = "Usage Tokens";
      $asset = $this->bankmsg($t->ASSET, 0, 0, 0, $assetname);
      $db->put($t->ASSET . '/0', $asset);
      $db->put($t->ASSETNAME . "/$assetname", 0);
      $accountdir = $t->ACCOUNT . "/$bankid";
      $seq = $this->getsequence();
      $db->put($this->acctlastkey($bankid), $seq);
      $db->put($this->acctlastrequestkey($bankid), 0);
      $mainkey = $this->acctbalancekey($bankid);
      $db->put("$mainkey/0", $this->bankmsg($t->BALANCE, $seq, 0, -1));
      $db->put($this->outboxhashkey($bankid), $this->outboxhash($bankid));
    } else {
      $privkey = $ssl->load_private_key($db->get($t->PRIVKEY), $passphrase);
      $this->privkey = $privkey;
    }
    $this->bankid = $this->db->get($this->t->PRIVKEYID);
  }

  // Bank sign a message
  function banksign($msg) {
    $sig = $this->ssl->sign($msg, $this->privkey);
    return "$msg:$sig";
  }

  // Make a bank signed message from $array
  // Takes multiple args
  function bankmsg() {
    $args = func_get_args();
    $msg = array_merge(array($this->bankid), $args);
    return $this->banksign($this->utility->makemsg($msg));
  }

  function commands() {
    $t = $this->t;
    if (!$this->commands) {
      $names = array($t->ID,
                     $t->GETLASTREQUEST,
                     $t->SEQUENCE,
                     $t->GETFEES,
                     $t->SPEND,
                     $t->INBOX,
                     $t->REMOVEINBOX,
                     $t->GETASSET,
                     $t->ASSET,
                     $t->GETOUTBOX,
                     $t->GETBALANCE);
      $commands = array();
      foreach($names as $name) {
        $commands[$name] = "do_$name";
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
    $parse = $parser->parse($msg);
    if (!$parse) {
      return $this->bankmsg($t->FAILED, $msg, $parser->errmsg);
    }
    foreach ($parse as $request) {
      $cmd = $request[1];
      echo "cmd: $cmd\n";
      $commands = $this->commands();
      $method = $commands[$cmd];
      if (!$method) {
        return $this->bankmsg($t->FAILED, $msg, "Unknown request: $cmd");
      }
      $this->$method($cmd);
    }
  }

}

// Test code

require_once "fsdb.php";
require_once "ssl.php";

$db = new fsdb("../trubancdb");
$ssl = new ssl();
$server = new server($db, $ssl, false, 'Trubanc');

 echo $server->process($server->bankmsg("fuckme", "up", "the", "ass"))

?>
