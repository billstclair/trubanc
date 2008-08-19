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
                        $t->OUTBOXHASH => array($t->BANKID,$t->TIME, $t->HASH),
                        $t->SPEND => array($t->BANKID,$t->TIME,$t->ID,
                                           $t->ASSET,$t->AMOUNT,$t->NOTE=>1),
                        $t->ASSET => array($t->BANKID,$t->ASSET,
                                           $t->SCALE,$t->PRECISION,$t->NAME),

                        $t->REGISTER => array($t->BANKID,$t->PUBKEY,$t->NAME=>1),
                        $t->SPENDACCEPT => array($t->BANKID,$t->TIME,$t->ID,$t->NOTE=>1),
                        $t->SPENDREJECT => array($t->BANKID,$t->TIME,$t->ID,$t->NOTE=>1),

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
                        $t->ATGETINBOX => array($t->MSG),
                        $t->ATBALANCE => array($t->MSG),
                        $t->ATSPEND => array($t->MSG),
                        $t->ATTRANFEE => array($t->MSG),
                        $t->ATASSET => array($t->MSG),
                        $t->ATPROCESSINBOX => array($t->MSG),
                        $t->ATSPENDACCEPT => array($t->MSG),
                        $t->ATSPENDREJECT => array($t->MSG),
                        $t->REQ => array($t->ID, $t->REQ),
                        $t->GETTIME => array($t->ID, $t->TIME)
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
    if (array_key_exists($t->BANKID, $args) && $bankid &&  $argsbankid != $bankid) {
      return "bankid mismatch, sb: $bankid, was: $argsbankid";
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
