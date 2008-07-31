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
    $needsig = false;
    $stack = array();
    $this->errstr = $str;
    $this->errmsg = false;
    $first = true;
    foreach ($tokens as $pos => $tok) {
      if ($first && $tok != '(') {
        $this->errmsg = "Message does not begin with left paren";
        return false;
      }
      $first = false;
      if ($tok == '(') {
        $needsig = true;
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
            $self->errmsg = "Missing key at $pos";
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
        if ($state && $state != ',' && $state != '(') {
          $this->errmsg = "Misplaced comma at $pos, state: $state";
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
        } elseif ($state == ':') {
          if (!$dict) $dict = array();
          $dict[$key] = $tok;
          //print_r($dict);
          $value = false;
        } elseif ($state == 'sig') {
          $id = $dict ? $dict[0] : false;
          if (!$id) {
            $this->errmsg = "Signature without ID at $pos";
            return false;
          }
          $keydb = $this->keydb;
          $pubkey = $keydb->get($id);
          if (!$pubkey && $dict[1] == 'id') {
            // May be the first time we've seen this ID.
            // If it's a key definition message, we've got all we need.
            $pubkey = $dict[2];
            $pubkeyid = $ssl->pubkey_id($pubkey);
            if ($id != $pubkeyid) {
              $pubkey = false;
            } else {
              $keydb->put($id, $pubkey);
            }
          }
          // Eventually, we'll need to look up the pubkey from the server here.
          // That will require init parms for the server & my <id>
          if (!$pubkey) {
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
            $needsig = true;
          } else {
            $res[] = $dict;
            $dict = false;
            $needsig = false;
          }
          $state = false;
        } else {
          $this->errmsg = "Misplaced value at $pos";
          return false;
        }
      }
    }
    if ($needsig) {
      $this->errmsg = "Premature end of message";
      return false;
    }
    $this->errstr = false;
    return $res;    
  }

  function tokenize($str) {
    $res = array();
    $i = 0;
    $realstart = false;
    $start = false;
    $delims = array('(',':',',',')','.');
    $escaped = false;
    $substr = '';
    for ($i=0; $i<strlen($str); $i++) {
      $chr = $str[$i];
      if (!$escaped && in_array($chr, $delims)) {
        if ($start) $res[$realstart] = $substr . substr($str, $start, $i - $start);
        $start = false;
        $realstart = false;
        $substr = '';
        $res[$i] = $chr;
      } elseif (!$escaped && $chr == "\\") {
        $escaped = true;
        if ($start) {
          $substr .= substr($str, $start, $i - $start);
          $start = $i+1;
        }
      } else {
        if (!$start) {
          $start = $i;
          $realstart = $i;
        }
        $escaped = false;
      }
    }
    if ($start) $res[$realstart] = $substr . substr($str, $start, $i-$start);
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
$privkey2 = $ssl->make_privkey(512);
$pubkey2 = $ssl->privkey_to_pubkey($privkey2);
$id2 = $ssl->pubkey_id($pubkey2);
$keydb->put($id, $pubkey);

$msg = "($id,\(1\,2\:3\\\\4\.5\),2,x:foo)";
$sig = $ssl->sign($msg, $privkey);
if (!$sig) {
  echo "No signature generated for $msg\n";
  return;
}
$msg = "$msg:$sig";

$msg2 = "($id,$msg,y:$msg)";
$sig2 = $ssl->sign($msg2, $privkey);
$msg .= ".$msg2:$sig2";

$msg3 = "($id2,id,$pubkey2)";
$sig3 = $ssl->sign($msg3, $privkey2);
$msg4 = "($id2,foo,bar)";
$sig4 = $ssl->sign($msg4, $privkey2);
$msg .= ".$msg3:$sig3.$msg4:$sig4.";

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
