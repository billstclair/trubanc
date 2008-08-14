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
  var $t;
  var $parser;
  var $utility;
  var $pubkeydb;

  // $db is an object that does put(key, value), get(key), and dir(key)
  // $ssl is an object that does the protocol of ssl.php
  function client($db, $ssl=false) {
    $this->db = $db;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->pubkeydb = $db->subdir($this->t->PUBKEY);
    $this->parser = new parser($this->pubkeydb, $ssl);
    $this->utility = new utility();
  }

}

?>
