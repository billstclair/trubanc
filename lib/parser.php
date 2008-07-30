<?PHP

  // parser.php
  // Parse "(id,[key:]value,...):signature" into an array, verifying signatures
  // Can separate multiple top-level forms with periods.
  // Values can be (id,...):signature forms.
  // Returns an array of top-level forms, each of which is an array.
  // Each of the form arrays has three distinguished keys:
  //  0 => The public key id
  //  'message' => The string of the message decoded in the array,
  //               including the open and close paren.
  //  'signature' => The signature

require_once "ssl.php";

class parser {

  var $keydb = false;
  var $ssl = false;
  var $errstr = false;
  var $errmsg = false;

  function parser($keydb, $ssl=false) {
    $this->keydb = $keydb;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
  }

  // Return an array or false if the parse could not be done,
  // or an ID couldn't be found, or a signature was bad.
  // left-paren, right-paren, comma, colon, and period are special chars.
  // They, and back-slash, are escaped by backslashes
  function parse($str) {
    $tokens = $this->tokenize($str);
    $state = false;
    $res = array();
    $dict = false;
    $start = false;
    $substr = false;
    $key = false;
    $value = false;
    $stack = array();
    $this->errstr = $str;
    $this->errmsg = false;
    foreach ($tokens as $pos => $tok) {
      if ($tok == '(') {
        if ($dict && $state && $state != ':' && $state != ',') {
          $this->errmsg = "Open paren not after colon or comma at $pos";
          return false;
        }
        if ($key && $state != ':') {
          $this->errmsg = "Missing key at $pos";
          return false;
        }
        if ($dict) {
          //echo "pushing\n";
          $stack[] = array($state, $dict, $start, $key);
          $state = false;
          $dict = false;
          $key = false;
        }
        $start = $pos;
        $state = '(';
      } elseif ($tok == ')') {
        if ($state == ',') {
          if ($key) {
            $self->errstr = "Missing key at $pos";
            return false;
          }
          if (!$dict) $dict = array();
          $dict[] = $value ? $value : '';
          //print_r($dict);
          $value = false;
        } elseif ($state == ':') {
          if (!$dict) $dict = array();
          $dict[$key] = $value ? $value : '';
          //print_r($dict);
          $value = false;
        } elseif ($state) {
          $this->errmsg = "Close paren not after value at $pos";
          return false;
        }
        $msg = substr($str, $start, $pos+1-$start);
        $state = ')';
      } elseif ($tok == ':') {
        if ($state == ')') {
          $state = 'sig';
        } elseif (!$value) {
          $this->errmsg = "Missing key before colon at $pos";
          return false;
        } else {
          $key = $value;
          $value = false;
          $state = ':';
        }
      } elseif ($tok == ',') {
        if ($state && $state != ',') {
          $this->errstr = "Misplaced comma at $pos";
          return false;
        }
        if (!$dict) $dict = array();
        $dict[] = $value ? $value : '';
        //print_r($dict);
        $value = false;
        $state = ',';
      } elseif ($tok == '.') {
        if ($state || count($stack) > 0) {
          $this->errmsg = "Misplaced period at $pos";
          return false;
        }
        if ($dict) $res[] = $dict;
        $dict = false;
        $key = false;
      } else {
        if ($state == '(' || $state == ',') {
          $value = $tok;
          $state = false;
        } elseif ($state == ':') {
          if (!$dict) $dict = array();
          $dict[$key] = $tok;
          //print_r($dict);
          $state = false;
        } elseif ($state == 'sig') {
          $id = $dict ? $dict[0] : false;
          if (!$id) {
            $this->errmsg = "Signature without ID at $pos";
            return false;
          }
          $keydb = $this->keydb;
          $pubkey = $keydb->get($id);
          if (!$key) {
            $this->errmsg = "No key for id: $id at $pos";
            return false;
          }
          $ssl = $this->ssl;
          if (!($ssl->verify($msg, $tok, $pubkey))) {
            $this->errmsg = "Failure to verify signature at $pos for $msg";
            return false;
          }
          $dict['message'] = $msg;
          $dict['signature'] = $tok;
          if (count($stack) > 0) {
            //echo "Popping\n";
            $value = $dict;
            $pop = array_pop($stack);
            $state = $pop[0];
            $dict = $pop[1];
            $start = $pop[2];
            $key = $pop[3];
            if ($key) $dict[$key] = $value;
            else $dict[] = $value;
          } else {
            $res[] = $dict;
            $dict = false;
          }
          $state = false;
        } else {
          $this->errmsg = "Misplaced value at $pos";
          return false;
        }
      }
    }
    $this->errstr = false;
    return $res;    
  }

  function tokenize($str) {
    $res = array();
    $i = 0;
    $start = false;
    $delims = array('(',':',',',')','.');
    for ($i=0; $i<strlen($str); $i++) {
      $chr = $str[$i];
      if (in_array($chr, $delims)) {
        if ($start) $res[$start] = substr($str, $start, $i - $start);
        $start = false;
        $res[$i] = $chr;
      } elseif (!$start) {
        $start = $i;
      }
    }
    if ($start) $res[$start] = substr($str, $start, $i-$start);
    //print_r($res);
    return $res;
  }

}

// Test code
/*
require_once "dictdb.php";
$keydb = new dictdb();
$ssl = new ssl();
$privkey = $ssl->make_privkey(512);
$pubkey = $ssl->privkey_to_pubkey($privkey);
$id = $ssl->pubkey_id($pubkey);
$keydb->put($id, $pubkey);
$msg = "($id,1,2,x:foo)";
$sig = $ssl->sign($msg, $privkey);
if (!$sig) {
  echo "No signature generated for $msg\n";
  return;
}
$msg = "$msg:$sig";
$msg2 = "($id,$msg,y:$msg)";
$sig2 = $ssl->sign($msg2, $privkey);
$msg = "$msg2:$sig2.$msg";
echo "$msg\n";
$parser = new parser($keydb, $ssl);
$res = $parser->parse($msg);
if ($res) print_r($res);
else {
  echo $parser->errmsg;
}
echo "\n";
*/

?>
