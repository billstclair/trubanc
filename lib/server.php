<?PHP

  // server.php
  // Implement the server protocol

require_once "tokens.php";

class server {

  var $db;
  var $ssl;
  var $t;

  function server($db, $ssl) {
    $this->db = $db;
    $this->ssl = $ssl;
    $this-$t = new tokens();
    $this->setupDB($db, $ssl, $t);
  }

  // Create a bankid and password
  function setupDB($db, $ssl, $t) {
    if ($db->get('sequence')
  }


}

?>