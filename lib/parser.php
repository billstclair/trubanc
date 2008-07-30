<?PHP

  // parser.php
  // Parse "(id, [key:]value, ...): signature" into an array

class parser {

  var $keydb = false;
  var $ssl = false;

  function parser($keydb) {
    $this->keydb = $keydb;
    $this->ssl = new ssl();
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
          $stack[] = array($state, $res, $dict, $start, $key);
          $state = false;
          $res = array();
          $dict = false;
          $start = $pos;
        }
        $state = false;
      } elseif ($tok == ')') {
        if ($state == ',') {
          if ($key) {
            $self->errstr = "Missing key at $pos";
            return false;
          }
          if (!$dict) $dict = array();
          $dict[] = $value ? $value : '';
          $value = false;
        } elseif ($state == ':') {
          if (!$dict) $dict = array();
          $dict[$key] = $value ? $value : '';
          $value = false;
        } elseif ($state) {
          $this->errmsg = "Close paren not after value at $pos";
          return false;
        }
        if ($dict) $res[] = $dict;
        $substr = substr($str, $start, $pos+1-$start);
        if (count($stack) > 0) {
          $newres = $res;
          $pop = array_pop($stack);
          $state = $pop[0];
          $res = ($pop[1]);
          $dict = ($pop[2]);
          $start = $pop[3];
          $key = $pop[4];
          if ($key) $dict[$key] = $newres;
          else $dict[] = $newres;
        }
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
        $value = false;
        $state = ',';
      } elseif ($tok == '.') {
        if ($state) {
          $this->errmsg = "Misplaced period at $pos";
          return false;
        }
      } else {
        if ($state == '(' || $state == ',') {
          $value = $tok;
          $state = false;
        } elseif ($state == ':') {
          if ($dict) $dict = array();
          $dict[$key] = $tok;
          $state = false;
        } elseif ($state = 'sig') {
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
          if (!($ssl->verify($msg, $tok, $pubkey))) {
            $this->errmsg = "Failure to verify signature at $pos";
            return false;
          }
        } else {
          $this->errmsg = "Misplaced value at $pos";
          return false;
        }
      }
    }
    return $res;    
  }

}