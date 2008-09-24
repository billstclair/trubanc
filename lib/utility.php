<?PHP

  // utility.php
  // Utility functions, bundled in a class

class utility {

  var $t;
  var $parser;
  var $bankgetter;
  var $patterns=false;

  function utility($t, $parser, $bankgetter) {
    $this->t = $t;
    $this->parser = $parser;
    $this->bankgetter = $bankgetter;
  }

  // Sort an array of numbers represented as strings.
  // Works even if they're too big to fit in a machine word.
  // Doesn't use bcmath, just prepends leading zeroes.
  // Does NOT clobber the array. Returns a new one.
  function bignum_sort($array) {
    $maxlen = 0;
    foreach ($array as $value) {
      $len = strlen($value);
      if ($len > $maxlen) $maxlen = $len;
    }
    $map = array();
    foreach ($array as $value) {
      $newval = str_repeat('0', $maxlen - strlen($value)) . $value;
      $map[$newval] = $value;
    }
    ksort($map);
    $res = array();
    foreach ($map as $newval => $value) {
      $res[] = $value;
    }
    return $res;
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
    foreach ($array as $key=>$value) {
      if ($i != 0) $msg .= ',';
      if ($key != $i) $msg .= "$key:";
      $msg .= $this->escape($value);
      $i++;
    }
    $msg .= ')';
    return $msg;
  }

  // Return the id for an asset
  function assetid($id, $scale, $precision, $name) {
    return sha1("$id,$scale,$precision,$name");
  }

  // Patterns for non-request data
  function patterns() {
    $t = $this->t;
    if (!$this->patterns) {
      $patterns = array(// Customer messages
                        $t->BALANCE => array($t->BANKID,$t->TIME,
                                             $t->ASSET, $t->AMOUNT, $t->ACCT=>1),
                        $t->OUTBOXHASH => array($t->BANKID, $t->TIME, $t->COUNT, $t->HASH),
                        $t->BALANCEHASH => array($t->BANKID, $t->TIME, $t->COUNT, $t->HASH),
                        $t->SPEND => array($t->BANKID,$t->TIME,$t->ID,
                                           $t->ASSET,$t->AMOUNT,$t->NOTE=>1),
                        $t->ASSET => array($t->BANKID,$t->ASSET,
                                           $t->SCALE,$t->PRECISION,$t->ASSETNAME),

                        $t->REGISTER => array($t->BANKID,$t->PUBKEY,$t->NAME=>1),
                        $t->SPENDACCEPT => array($t->BANKID,$t->TIME,$t->ID,$t->NOTE=>1),
                        $t->SPENDREJECT => array($t->BANKID,$t->TIME,$t->ID,$t->NOTE=>1),
                        $t->GETOUTBOX =>array($t->BANKID, $t->REQ),
                        $t->GETTIME => array($t->BANKID, $t->TIME),

                        // Bank signed messages
                        $t->FAILED => array($t->MSG, $t->ERRMSG),
                        $t->TOKENID => array($t->TOKENID),
                        $t->BANKID => array($t->BANKID),
                        $t->REGFEE => array($t->BANKID, $t->TIME, $t->ASSET, $t->AMOUNT),
                        $t->TRANFEE => array($t->BANKID, $t->TIME, $t->ASSET, $t->AMOUNT),
                        $t->TIME => array($t->ID, $t->TIME),
                        $t->INBOX => array($t->TIME, $t->MSG),
                        $t->ATREGISTER => array($t->MSG),
                        $t->ATOUTBOXHASH => array($t->MSG),
                        $t->ATBALANCEHASH => array($t->MSG),
                        $t->ATGETINBOX => array($t->MSG),
                        $t->ATBALANCE => array($t->MSG),
                        $t->ATSPEND => array($t->MSG),
                        $t->ATTRANFEE => array($t->MSG),
                        $t->ATASSET => array($t->MSG),
                        $t->ATPROCESSINBOX => array($t->MSG),
                        $t->ATSPENDACCEPT => array($t->MSG),
                        $t->ATSPENDREJECT => array($t->MSG),
                        $t->ATGETOUTBOX => array($t->MSG),
                        $t->REQ => array($t->ID, $t->REQ)
                        );
      $this->patterns = $patterns;
    }
    return $this->patterns;
  }

  function match_pattern($req) {
    $t = $this->t;
    $parser = $this->parser;
    $patterns = $this->patterns();
    $pattern = $patterns[$req[1]];
    if (!$pattern) return "Unknown request: '" . $req[1] . "'";
    $pattern = array_merge(array($t->CUSTOMER,$t->REQUEST), $pattern);
    $args = $parser->matchargs($req, $pattern);
    if (!$args) {
      $msg = $parser->get_parsemsg($req);
      return "Request doesn't match pattern for '" . $req[1] . "': " .
        $parser->formatpattern($pattern) . " $msg";
    }
    $argsbankid = $args[$t->BANKID];
    $bankid = $this->bankgetter->bankid();
    if (array_key_exists($t->BANKID, $args) && $bankid && $argsbankid != $bankid) {
      return "bankid mismatch, sb: $bankid, was: $argsbankid";
    }
    if (strlen($args[$t->NOTE]) > 4096) {
      return "Note too long. Max: 4096 chars";
    }
    return $args;
  }

  // Parse and match a message.
  // Returns an array mapping parameter names to values.
  // Returns a string if parsing or matching fails.
  function match_message($msg) {
    $parser = $this->parser;

    $reqs = $parser->parse($msg);
    if (!$reqs) return $parser->errmsg || "Parse failed";
    return $this->match_pattern($reqs[0]);
  }

  // Return the hash of a directory, $key, of bank-signed messages.
  // The hash is of the user messages wrapped by the bank signing.
  // $newitems is a new item or an array of new items, not bank-signed.
  // $removed_names is an array of names in the $key dir to remove.
  // $unpacker is an object on which to call the unpack_bankmsg()
  // method with a single-arg, a bank-signed message. It returns
  // a parsed and matched $args array whose $t->MSG element is
  // the parsed user message wrapped by the bank signing.
  // Returns array('hash'=>$hash, 'count'=>$count)
  // Where $hash is the sha1 hash, and $count is the number of items
  // hashed.
  // Returns false if there's a problem.
  function dirhash($db, $key, $unpacker, $newitem=false, $removed_names=false) {
    $parser = $this->parser;
    $t = $this->t;

    $contents = $db->contents($key);
    $items = array();
    foreach ($contents as $name) {
      if (!$removed_names || !in_array($name, $removed_names)) {
        $msg = $db->get("$key/$name");
        $args = $unpacker->unpack_bankmsg($msg);
        if (!$args || is_string($args)) return false;
        $req = $args[$t->MSG];
        if (!$req) return false;
        $msg = $parser->get_parsemsg($req);
        if (!$msg) return false;
        $items[] = $msg;
      }
    }
    if ($newitem) {
      if (is_string($newitem)) $items[] = $newitem;
      else $items = array_merge($items, $newitem);
    }
    sort($items);
    $hash = sha1(implode('.', array_map('trim', $items)));
    return array($t->HASH => $hash, $t->COUNT => count($items));
  }

  // Compute the balance hash as array($t->HASH => $hash, $t->COUNT => $hashcnt)
  // $id is the ID of the account.
  // $unpacker must have balancekey() and unpack_bankmsg() methods.
  // $acctbals is array($acct => array($assetid => $msg))
  function balancehash($db, $id, $unpacker, $acctbals) {
    $t = $this->t;
    $u = $this->u;

    $hash = '';
    $hashcnt = 0;
    $balancekey = $unpacker->balancekey($id);
    $accts = $db->contents($balancekey);
    $needsort = false;
    foreach ($acctbals as $acct => $bals) {
      if (!in_array($acct, $accts)) {
        $accts[] = $acct;
        $needsort = true;
      }
    }
    if ($needsort) sort($accts);
    foreach ($accts as $acct) {
      $newitems = array();
      $removed_names = array();
      $newacct = $acctbals[$acct];
      if ($newacct) {
        foreach ($newacct as $assetid => $msg) {
          $newitems[] = $msg;
          $removed_names[] = $assetid;
        }
        $hasharray = $this->dirhash($db, "$balancekey/$acct", $unpacker,
                                    $newitems, $removed_names);
        if ($hash != '') $hash .= '.';
        $hash .= $hasharray[$t->HASH];
        $hashcnt += $hasharray[$t->COUNT];
      }
    }
    if ($hashcnt > 1) $hash = sha1($hash);
    return array($t->HASH => $hash, $t->COUNT => $hashcnt);
  }

  // Take the values in the passed array and return an array with
  // those values as its keys mapping to $value.
  function array_to_keys($arr, $value=true) {
    $res = array();
    foreach($arr as $v) {
      $res[$v] = $value;
    }
    return $res;
  }

}

// Test code
/*
$ut = new utility();
print_r($ut->bignum_sort(array("10","1","20", "2", "99999", "123456")));
*/

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
