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

  var $id;
  var $privkey;

  // $db is an object that does put(key, value), get(key), and dir(key)
  // $ssl is an object that does the protocol of ssl.php
  function client($db, $ssl=false) {
    $this->db = $db;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->pubkeydb = $db->subdir($this->t->PUBKEY);
    $this->parser = new parser($this->pubkeydb, $ssl);
    $this->u = new utility();
  }

  // API Methods
  // All return false on success or an error string on failure

  // Create a new user with the given passphrase, error if already there.
  // If $privatekey is a string, use that.
  // If it is an integer, default 3072, create a new private key with that many bits
  function newuser($passphrase, $privkey=3072) {
    $db = $this->db;
    $t = $this->t;
    $ssl = $this->ssl;

    $hash = $this->passphrasehash($passphrase);
    if ($db->get($t->PRIVKEY . "/$hash")) {
        return "Passphrase already has an associated private key";
    }
    if (!is_string($privkey)) {
      if (!is_number($privkey)) return "privkey arg not a string or number";
      $privkey = $ssl->make_privkey($privkey, $passphrase);
    }
    $privkeystr = $privkey;
    $privkey = $ssl->load_private_key($privkey, $passphrase);
    if (!$privkey) return "Could not load private key";
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    $id = $ssl->pubkey_id($pubkey);
    $db->put($t->PRIVKEY . "/$hash", $privkeystr);
    $db->put($t->PUBKEY . "/$id", $pubkey);

    $this->id = $id;
    $this->privkey = $privkey;
    return false;
  }

  function login($passphrase) {
    $db -> $this->db;
    $t = $this->t;
    $ssl = $this->ssl;

    $hash = $this->passphrasehash($passphrase);
    $privkey = $db->GET($t->PRIVKEY . "/$hash");
    if (!$privkey) return "No account for passphrase in database";
    $privkey = $ssl->load_private_key($privkey, $passphrase);
    if (!$privkey) return "Could not load private key";
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    $id = $ssl->pubkey_id($pubkey);

    $this->privkey = $privkey;
    $this->id = $id;
    return false;
  }

  // End of API methods

  function passphrasehash($passphrase) {
    return sha1(trim($passphrase));
  }

}

?>
