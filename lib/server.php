<?PHP

  // server.php
  // Implement the server protocol

require_once "tokens.php";

class server {

  var $db;
  var $ssl;
  var $t;
  var $passphrase;
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
    $this->passphrase = $passphrase;
    $this->bankname = $bankname;
    $this->setupDB();
  }

  function privkey() {
    if (!$this->privkey) {
      $this->privkey = $this->db->get($this->t->PRIVKEY);
    }
    return $this->privkey;
  }

  function bankid() {
    if (!$this->bankid) {
      $this->bankid = $this->db->get($this->t->PRIVKEYID);
    }
  }

  function getsequence() {
    $db = $this->db;
    $t = $this->t;
    $fp = $db->lock($t->SEQUENCE);
    $res = $db->get($t->SEQUENCE) + 1;
    $db->put($t->SEQUENCE, $res);
    $db->unlock($fp);
    return $res;
  }

  function accountdir($id) {
    return $this->t->ACCOUNT . "/$id" . '/';
  }

  function accountlastkey($id) {
    return $this->accountdir($id) . $this->t->LAST;
  }

  function balancekey($id) {
    return $this->accountdir($id) . $this->t->BALANCE;
  }

  function acctbalancekey($id, $acct='main') {
    return $this->balancekey() . "/$acct");
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

  function outboxhash($id, $privkey) {
    $db = $this->db;
    $tranlist = implode(',', $db->contents($this->outboxkey()));
    return sha1($tranlist);
  }

  // Create a bankid and password
  function setupDB() {
    $db = $this->db;
    $ssl = $this->ssl;
    $t = $this->t;
    if (!$db->get($t->SEQUENCE)) $db->put($t->SEQUENCE) = '0';
    if (!$db->get($t->PRIVKEY)) {
      $privkey = $ssl->make_privkey(4096, $this->passphrase);
      $pubkey = $ssl->privkey_to_pubkey($privkey);
      $bankid = $ssl->pubkey_id($pubkey);
      $db->put($t->PRIVKEY, $privkey);
      $db->put($t->PRIVKEYID, $bankid);
      $idmsg = $this->bankmsg(array($bankid, $t->PUBKEY, $pubkey, $this->bankname));
      $db->put($t->PUBKEY . "/$bankid", $pubkey);
      $db->put($t->PUBKEYSIG . "/$bankid", $idmsg);
      $db->put($t->REGFEE, 10);
      $db->put($t->REGFEESIG, $bankmsg(array($bankid, $t->REGFEE, $this->getsequence(), 0, 10)));
      $db->put($t->TRANFEE, 2);
      $db->put($t->TRANFEESIG, $bankmsg(array($bankid, $t->TRANFEE, $this->getsequence(), 0, 2)));
      $db->put($t->ASSET . '/' . $t->LAST, 0);
      $assetname = "Usage Tokens";
      $asset = $this->bankmsg(array($bankid, $t->ASSET, 0, 0, 0, $assetname));
      $db->put($t->ASSET . '/0', $asset);
      $db->put($t->ASSETNAME, $assetname);
      $accountdir = $t->ACCOUNT . "/$bankid";
      $db->put($this->accountlastkey($bankid), 0);
      $mainkey = $this->acctbalancekey($bankid);
      $db->put("$mainkey/0", $bankmsg(array($bankid, $t->BALANCE, $this->getsequence(), 0, -1)));
      $db->put($this->outboxhashkey($bankid), $this->outboxhash($bankid);
    }
  }

  // Escape a string for inclusion in a message
  function escape($str) {
    $res = '';
    $ptr = 0;
    for ($i=0; $i<strlen($str); $i++) {
      if (!(strpos("(),:.\\", substr($str, $i, 1)) === false)) {
        $res .= substr($str, $ptr, $i - $ptr) . "\\";
        $ptr = $i;
      }
    }
    if ($ptr == 0) return $str;
    $res .= substr($str, $ptr);
    return $res;
  }

  // Make an unsigned message from $array
  function makemsg($array) {
    $msg = "(";
    $i = 0;
    foreach ($array as $key->$value) {
      if ($i != 0) $msg .= ',';
      if ($key != $i) $msg .= "$key:";
      $msg .= $this->escape($value);
      $i++;
    }
    $msg .= ')';
    return $this->banksign($msg);
  }

  // Bank sign a message
  function banksign($msg) {
    $sig = $this->ssl->sign($msg, $this->privkey(), $this->passphrase);
    return "$msg:$sig";
  }

  // Make a bank signed message from $array
  function bankmsg($array) {
    return $this->banksign($this->makemsg($array));
  }


}

?>
