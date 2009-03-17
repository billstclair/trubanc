<?php

  // parser.php
  // Parse "(id,[key:]value,...):signature" into an array, verifying signatures
  // Can separate multiple top-level forms with periods.
  // Values can be (id,...):signature forms.
  // Returns an array of top-level forms, each of which is an array.
  // Each of the form arrays has three distinguished keys:
  //  0 => The public key id

require_once "ssl.php";
require_once "perf.php";

class parser {

  var $keydb = false;
  var $ssl = false;
  var $keydict = false;

  var $msgkey = '%msg%';        // the text of the message is stored here

  var $errstr = false;
  var $errmsg = false;

  var $alwaysverifysigs = false;
  var $verifysigs = true;

  function parser($keydb, $ssl=false) {
    $this->keydb = $keydb;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->keydict = array();         // validated keys
  }

  function verifysigs($newvalue=null) {
    if ($newvalue === null) return $this->verifysigs;
    $this->verifysigs = $newvalue;
    return $newvalue;
  }

  // Return an array or false if the parse could not be done,
  // or an ID couldn't be found, or a signature was bad.
  // left-paren, right-paren, comma, colon, and period are special chars.
  // They, and back-slash, are escaped by backslashes
  // If $verifysigs is false, don't verify PGP signatures.
  // If $verifysigs is unspecified of 'default', use $this->verifysigs
  // as the value (default: true)
  function parse($str, $verifysigs='default') {
    $idx = perf_start('parser->parse');
    $res = $this->parse_internal($str, $verifysigs);
    perf_stop($idx);
    return $res;
  }

  function parse_internal($str, $verifysigs) {
    if ($verifysigs == 'default') $verifysigs = $this->verifysigs;
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
          $dict[] = ($value === FALSE) ? '' : $value;
          //print_r($dict);
          $value = false;
        } elseif ($state == ':') {
          if (!$dict) $dict = array();
          $dict[$key] = ($value === FALSE) ? '' : $value;
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
        $dict[] = ($value === FALSE) ? '' : $value;
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
          if (!($id === '0' && $dict[1] == 'bankid')) {
            if (!$id) {
              $this->errmsg = "Signature without ID at $pos";
              return false;
            }
            $keydict = $this->keydict;
            $pubkey = $keydict[$id];
            if (!$pubkey && ($dict[1] == 'register' || $dict[1] == 'bankid')) {
              // May be the first time we've seen this ID.
              // If it's a key definition message, we've got all we need.
              $pubkey = ($dict[1] == 'register') ? $dict[3] : $dict[2];
              $pubkeyid = $this->ssl->pubkey_id($pubkey);
              if ($id != $pubkeyid) $pubkey = false;
              else {
                $keydict[$id]= $pubkey;
                $this->keydict = $keydict;
              }
            }
            if (!$pubkey) {
              $keydb = $this->keydb;
              $pubkey = $keydb->get($id);
              if ($pubkey) {
                if ($id != $this->ssl->pubkey_id($pubkey)) {
                  $this->errmsg = "Pubkey doesn't match id: $id";
                  return false;
                }
                $keydict[$id] = $pubkey;
                $this->keydict = $keydict;
              }
            }
            if (!$pubkey) {
              // The client will need to look up and cache the pubkey from the server here.
              $this->errmsg = "No key for id: $id at $pos";
              return false;
            }
            if ($verifysigs || $this->alwaysverifysigs) {
              $ssl = $this->ssl;
              if (!($ssl->verify($msg, $tok, $pubkey))) {
                $this->errmsg = "Signature verification failed at $pos";
                return false;
              }
            }
          }
          $dict[$this->msgkey] = substr($str, $start, $pos + strlen($tok) - $start);
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
    $idx = perf_start('parser->tokenize');
    $res = $this->tokenize_internal($str);
    perf_stop($idx);
    return $res;
  }

  function tokenize_internal($str) {
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

  // Return the message string that parsed into the array in $parse
  function get_parsemsg($parse) {
    return $parse[$this->msgkey];
  }

  // Return just the message part of a signed message, not including the signature.
  // Assumes that the message will parse.
  function unsigned_message($msg) {
    $pos = strpos('):', $msg);
    if ($pos === FALSE) return $msg;
    return substr($msg, 0, $pos+1);
  }

  // Return the first message in a list of them.
  // Assumes that message parses correctly.
  function first_message($msg) {
    while (true) {
      $pos = strpos($msg, '.', $pos+1);
      if ($pos === FALSE) return $msg;
      else {
        if ($pos == 0 || $msg[$pos-1] != '\\') return substr($msg, 0, $pos);
      }
    }
  }

  // $parse is an array with numeric and string keys
  // $pattern is an array with numeric keys with string value, and
  // non-numeric keys with non-false values.
  // A numeric key in $pattern must match a numeric key in $parse.
  // A non-numeric key in $pattern must correspond to a numeric key in $parse
  // at the element number in $pattern or the same non-numeric key in $parse.
  // The result maps the non-numeric keys and values in $pattern and
  // their positions, to the matching values in $parse.
  // See the test code below for examples.
  function matchargs($parse, $pattern) {
    $i = 0;
    $res = array();
    foreach ($pattern as $key => $value) {
      if (is_numeric($key)) {
        $name = $value;
        $optional = false;
      } else {
        $name = $key;
        $optional = true;
      }
      $val = $parse[$i];
      if ($val === NULL) $val = $parse[$name];
      if (!$optional && $val === NULL) return false;
      if (!($val === NULL)) {
        $res[$name] = $val;
        $res[$i] = $val;
      }
      $i++;
    }
    $msgkey = $this->msgkey;
    foreach ($parse as $key => $value) {
      if ($key != $msgkey && $res[$key] === NULL) return false;
    }
    $res[$msgkey] = $parse[$msgkey];
    return $res;
  }

  function formatpattern($pattern) {
    $res = '(';
    $comma = false;
    foreach($pattern as $key => $value) {
      if ($comma) $res .= ',';
      $comma = true;
      if (is_numeric($key)) $res .= "<$value>";
      else $res .= "$key=<$key>";
    }
    $res .= ')';
    return $res;
  }

  // Remove the signatures out of a message
  function remove_signatures($msg) {
    $res = '';
    while ($msg) {
      $tail = strstr($msg, "):\n");
      $extralen = 1;
      $matchlen = 3;
      $tail2 = strstr($msg, "\\)\\:\n");
      if (strlen($tail2) > strlen($tail)) {
        $tail = $tail2;
        $extralen = 2;
        $matchlen = 5;
      }
      $i = strlen($msg) - strlen($tail);
      $res .= substr($msg, $idx, $i + $extralen);
      $msg = substr($tail, $matchlen);
      $dotpos = strpos($msg, '.');
      $leftpos = strpos($msg, '(');
      $commapos = strpos($msg, ',');
      if ($dotpos === FALSE) $dotpos = $leftpos;
      elseif (!($leftpos === FALSE)) $dotpos = min($dotpos, $leftpos);
      if ($dotpos === FALSE) $dotpos = $commapos;
      elseif (!($commapos === FALSE)) $dotpos = min($dotpos, $commapos);
      $parenpos = strpos($msg, ')');
      if (!($parenpos === false) &&
          ($dotpos === FALSE || $parenpos < $dotpos)) $msg = substr($msg, $parenpos);
      elseif ($dotpos) {
        $res .= "\n";
        $msg = substr($msg, $dotpos);
      } else break;
    }
    return str_replace(",(", ",\n(", $res);
  }

}

// Test code
/*
$p = new parser(false);
echo "RES: " . $p->remove_signatures("(foo,bar,bletch,(1,2,3):
fjdkf
fjdkf
jfkd
):
jdfksal
jfdkla;
.(a,b,c):
fjkdsal
fjkdsla");
echo "\n";
*/

/*
$parser = new parser(false);
$pattern = array('x', 'y', 'bletch'=>1);
echo $parser->formatpattern($pattern) . "\n";
$args = $parser->matchargs(array('foo','bar','3'), $pattern);
echo "1: ";
if ($args) print_r($args);
else echo "Didn't match, and I expected it to\n";
$args = $parser->matchargs(array('foo','bar','bletch'=>2), $pattern);
echo "2: ";
if ($args) print_r($args);
else echo "Didn't match, and I expected it to\n";
$args = $parser->matchargs(array('foo','bar','nomatch'=>2), $pattern);
echo "3: ";
if ($args) {
  echo "Didn't expect this match:\n";
  print_r($args);
}
else echo "Didn't match, as expected\n";
$args = $parser->matchargs(array('foo',''), $pattern);
echo "4: ";
if ($args) print_r($args);
else echo "Didn't match, and I expected it to\n";
$args = $parser->matchargs(array('foo','y'=>''), $pattern);
echo "5: ";
if ($args) print_r($args);
else echo "Didn't match, and I expected it to\n";
$args = $parser->matchargs(array('foo'), $pattern);
echo "6: ";
if ($args) {
  echo "Didn't expect this match:\n";
  print_r($args);
}
else echo "Didn't match, as expected\n";
*/
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
$keydb->put($id2, $pubkey2);
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
if ($res) {
  print_r($res);
} else {
  echo $parser->errmsg;
}
echo "\n";
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

