<?PHP

  // server.php
  // Implement the server protocol

require_once "tokens.php";
require_once "ssl.php";
require_once "utility.php";
require_once "parser.php";

class server {

  var $db;
  var $ssl;
  var $t;
  var $parser;
  var $utility;
  var $pubkeydb;
  var $bankname;
  var $regfee;
  var $tranfee;

  var $privkey;
  var $bankid;

  // $db is an object that does put(key, value), get(key), and dir(key)
  // $ssl is an object that does the protocol of ssl.php
  // $bankname is used to initialize the bank name in a new database. Ignored otherwise.
  function server($db, $ssl=false, $passphrase=false, $bankname='') {
    $this->db = $db;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->pubkeydb = $db->subdir($this->t->PUBKEY);
    $this->parser = new parser($this->pubkeydb, $ssl);
    $this->utility = new utility();
    $this->bankname = $bankname;
    $this->setupDB($passphrase);
  }

  function gettime() {
    $db = $this->db;
    $t = $this->t;
    $lock = $db->lock($t->TIME);
    $res = bcadd($db->get($t->TIME), 1);
    $db->put($t->TIME, $res);
    $db->unlock($lock);
    return $res;
  }

  function getacctlast($id) {
    return $this->db->get($this->acctlastkey($id));
  }

  function getacctreq($id) {
    return $this->db->get($this->acctreqkey($id));
  }

  function accountdir($id) {
    return $this->t->ACCOUNT . "/$id" . '/';
  }

  function accttimekey($id) {
    return $this->accountdir($id) . $this->t->TIME;
  }

  function acctlastkey($id) {
    return $this->accountdir($id) . $this->t->LAST;
  }

  function acctreqkey($id) {
    return $this->accountdir($id) . $this->t->REQ;
  }

  function balancekey($id) {
    return $this->accountdir($id) . $this->t->BALANCE;
  }

  function acctbalancekey($id, $acct='main') {
    return $this->balancekey($id) . "/$acct";
  }

  function assetbalancekey($id, $asset, $acct='main') {
    return $this->acctbalancekey($id, $acct) . "/$asset";
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

  function outboxdir($id) {
    return $this->accountdir($id) . $this->t->OUTBOX;
  }

  function outboxhash($id, $transtime, $newitem=false) {
    $parser = $this->parser;
    $db = $this->db;
    $dir = $this->outboxkey($id);
    $contents = $this->db->contents($this->outboxkey($id));
    if ($newitem) $contents[] = $transtime;
    $contents = $this->utility->bignum_sort($contents);
    $unhashed = '';
    foreach ($contents as $time) {
      if (bccomp($time, $transtime) <= 0) {
        if ($time == $transtime) $item = $newitem;
        else {
          $args = unpack_bankmsg($db->get("$dir/$time"));
          $item = $args[$t->MSG];
        }
        if ($unhashed != '') $unhashed .= '.';
        $unhashed .= trim($item);
      }
    }
    $hash = sha1($unhashed);
    return $hash;
  }

  function outboxhashmsg($id, $transtime) {
    return $this->bankmsg($this->t->OUTBOXHASH,
                          $this->bankid,
                          $this->getacctlast($id),
                          $this->outboxhash($id, $transtime));
  }

  function assetID($id, $scale, $precision, $name) {
    return sha1("$id,$scale,$precision,$name");
  }

  function is_asset($assetid) {
    return $this->db->get($this->t->ASSET . "/$assetid");
  }

  function lookup_asset($assetid) {
    $t = $this->t;
    $asset = $this->is_asset($assetid);
    return $this->unpack_bankmsg($asset, $t->ATASSET, $t->ASSET);
  }

  function lookup_asset_name($assetid) {
    $assetreq = $this->lookup_asset($assetid);
    return $assetreq[$this->t->NAME];
  }

  function is_alphanumeric($char) {
    $ord = ord($char);
    return ($ord >= ord('0') && $ord <= ord('9')) ||
      ($ord >= ord('A') && $ord <= ord('Z')) ||
      ($ord >= ord('a') && $ord <= ord('z'));
  }

  function is_acct_name($acct) {
    for ($i=0; $i<strlen($acct); $i++) {
      if (!$this->is_alphanumeric(substr($acct, $i, 1))) return false;
    }
    return true;
  }

  // Initialize the database, if it needs initializing
  function setupDB($passphrase) {
    $db = $this->db;
    $ssl = $this->ssl;
    $t = $this->t;
    $bankname = $this->bankname;
    if (!$db->get($t->PRIVKEY)) {
      // http://www.rsa.com/rsalabs/node.asp?id=2004 recommends that 3072-bit
      // RSA keys are equivalent to 128-bit symmetric keys, and they should be
      // secure past 2031.
      $privkey = $ssl->make_privkey(3072, $passphrase);
      $db->put($t->PRIVKEY, $privkey);
      $privkey = $ssl->load_private_key($privkey, $passphrase);
      $this->privkey = $privkey;
      $pubkey = $ssl->privkey_to_pubkey($privkey);
      $bankid = $ssl->pubkey_id($pubkey);
      $this->bankid = $bankid;
      $db->put($t->TIME, 0);
      $db->put($t->BANKID, $this->bankmsg($t->BANKID, $bankid));
      $regmsg = $this->bankmsg($t->REGISTER, $bankid, "\n$pubkey", $bankname);
      $regmsg = $this->bankmsg($t->ATREGISTER, $regmsg);
      $db->put($t->PUBKEY . "/$bankid", $pubkey);
      $db->put($t->PUBKEYSIG . "/$bankid", $regmsg);
      $token_name = "Asset Tokens";
      if ($this->bankname) $token_name = "$bankname $token_name";
      $tokenid = $this->assetid($bankid, 0, 0, $token_name);
      $this->tokenid = $tokenid;
      $db->put($t->TOKENID, $this->bankmsg($t->TOKENID, $tokenid));
      $asset = $this->bankmsg($t->ASSET, $bankid, $tokenid, 0, 0, $token_name);
      $db->put($t->ASSET . "/$tokenid", $this->bankmsg($t->ATASSET, $asset));
      $this->regfee = 10;
      $db->put($t->REGFEE, $this->bankmsg($t->REGFEE, $bankid, 0, $tokenid, $this->regfee));
      $this->tranfee = 2;
      $db->put($t->TRANFEE, $this->bankmsg($t->TRANFEE, $bankid, 0, $tokenid, $this->tranfee));
      $accountdir = $t->ACCOUNT . "/$bankid";
      $db->put($this->accttimekey($bankid), 0);
      $db->put($this->acctlastkey($bankid), 0);
      $db->put($this->acctreqkey($bankid), 0);
      $mainkey = $this->acctbalancekey($bankid);
      // $t->BALANCE => array($t->BANKID,$t->TIME, $t->ASSET, $t->AMOUNT, $t->ACCT=>1),
      $msg = $this->bankmsg($t->BALANCE, $bankid, 0, $tokenid, -1);
      $msg = $this->bankmsg($t->ATBALANCE, $msg);
      $db->put("$mainkey/$tokenid", $msg);
      $db->put($this->outboxhashkey($bankid),
               $this->bankmsg($t->ATOUTBOXHASH, $this->outboxhashmsg($bankid, 0)));
    } else {
      $privkey = $ssl->load_private_key($db->get($t->PRIVKEY), $passphrase);
      $this->privkey = $privkey;
      $this->bankid = $this->unpack_bank_param($db, $t->BANKID);
      $this->tokenid = $this->unpack_bank_param($db, $t->TOKENID);
      $this->regfee = $this->unpack_bank_param($db, $t->REGFEE, $t->AMOUNT);
      $this->tranfee = $this->unpack_bank_param($db, $t->TRANFEE, $t->AMOUNT);
    }
  }

  // Unpack wrapped initialization parameter
  function unpack_bank_param($db, $type, $key=false) {
    if (!$key) $key = $type;
    return $this->unpack_bankmsg($db->get($type), $type, false, $key, true);
  }

  // Bank sign a message
  function banksign($msg) {
    $sig = $this->ssl->sign($msg, $this->privkey);
    return "$msg:\n$sig";
  }


  // Make an unsigned message from the args.
  // Takes as many args as you care to pass.
  function makemsg() {
    $t = $this->t;
    $utility = $this->utility;

    $req = func_get_args();
    $args = $this->match_pattern($req);
    // I don't like this at all, but I don't know what else to do
    if (!$args) return call_user_func_array(array($this, 'failmsg'), $req);
    if (is_string($args)) return $this->failmsg($args);
    $msg = '(';
    $skip = false;
    foreach ($args as $k => $v) {
      if (is_int($k) && !$skip) {
        if ($msg != '(') $msg .= ',';
        $msg .= $utility->escape($v);
      } elseif ($k == $t->MSG) {
        $skip = true;
        $msg .= ",$v";
      }
    }
    $msg .= ')';
    return $msg;
  }

  // Make a bank signed message from the args.
  // Takes as many args as you care to pass
  function bankmsg() {
    $req = func_get_args();
    $req = array_merge(array($this->bankid), $req);
    $msg = call_user_func_array(array($this, 'makemsg'), $req);
    return $this->banksign($msg);
  }

  // Takes as many args as you care to pass
  function failmsg() {
    $args = func_get_args();
    $msg = array_merge(array($this->bankid, $this->t->FAILED), $args);
    return $this->banksign($this->utility->makemsg($msg));
  }

  function maybedie($msg, $die) {
    if ($die) die("$msg\n");
    return $msg;
  }

  // Reverse the bankmsg() function, optionally picking one field to return
  function unpack_bankmsg($msg, $type=false, $subtype=false, $idx=false, $fatal=false) {
    $bankid = $this->bankid;
    $parser = $this->parser;
    $t = $this->t;

    $reqs = $parser->parse($msg);
    if (!$reqs) return $this->maybedie($parser->errmsg, $fatal);
    $req = $reqs[0];
    $args = $this->match_pattern($req);
    if (is_string($args)) $this->maybedie("While matching bank-wrapped message: $args", $fatal);
    if ($args[$t->CUSTOMER] != $bankid && $bankid) {
      return $this->maybedie("bankmsg not from bank", $fatal);
    }
    if ($type && $args[$t->REQUEST] != $type) {
      if ($fatal) die("Bankmsg wasn't of type: $type\n");
      return false;
    }
    if (!$subtype) {
      if ($idx) {
        $res = $args[$idx];
        return $this->maybedie($res, $fatal && !$res);
      }
      return $args;
    }

    $msg = $args[$t->MSG];      // this is already parsed
    if (!$msg) return $this->maybedie("No wrapped message", $fatal);
    $req = $msg;
    $args = $this->match_pattern($req);
    if (is_string($args)) return $this->maybedie("While matching wrapped customer message: $args", $fatal);
    if (is_string($subtype) && !$args[$t->REQUEST] == $subtype) {
      if ($fatal) die("Wrapped message wasn't of type: $subtype\n");
      return false;
    }
    if ($idx) {
      $res = $args[$idx];
      return $this->maybedie($res, $fatal && !$res);
    }
    return $args;
  }

  function scaninbox($id) {
    $db = $this->db;
    $inboxkey = $this->inboxkey($id);
    $times = $db->contents($inboxkey);
    $res = array();
    foreach ($times as $time) {
      $res[] = $db->get("$inboxkey/$time");
    }
    return $res;
  }

  function signed_balance($time, $asset, $amount, $acct=false) {
    if ($acct) {
      return $this->bankmsg($this->t->BALANCE, $time, $asset, $amount, $acct);
    } else {
      return $this->bankmsg($this->t->BALANCE, $time, $asset, $amount);
    }
  }

  function signed_spend($time, $id, $assetid, $amount, $note=false, $acct=false) {
    $bankid = $this->bankid;
    if ($note && $acct) {
      return $this->bankmsg($this->t->SPEND, $bankid, $time, $id, $assetid, $amount, $note, $acct);
    } elseif ($note) {
      return $this->bankmsg($this->t->SPEND, $bankid, $time, $id, $assetid, $amount, $note);
    } elseif ($acct) {
      return $this->bankmsg($this->t->SPEND, $bankid, $time, $id, $assetid, $amount, "acct=$acct");
    } else return $this->bankmsg($this->t->SPEND, $bankid, $time, $id, $assetid, $amount);
  }

  function enq_time($id) {
    $db = $this->db;
    $time = $this->gettime();
    $key = $this->accttimekey($id);
    $lock = $db->lock($key);
    $q = $db->get($key);
    if (!$q) $q = $time;
    else $q .= ",$time";
    $db->put($q);
    $db->unlock($lock);
    return $q;
  }

  function deq_time($id, $time) {
    $db = $this->db;
    $key = $this->accttimekey($id);
    $lock = $db->lock($key);
    $q = $db->get($key);
    $res = false;
    if ($q) {
      $times = explode(',', $q);
      foreach ($times as $k => $v) {
        if ($v == $time) {
          $res = $time;
          unset($times[$k]);
          $q = implode(',', $times);
          $db->put($key, $q);
          $db->put($this->acctlastkey($id), $time);
        }
      }
    }
    $db->unlock($lock);
    return $res;
  }

  function match_bank_signed_message($inmsg) {
    $t = $this->t;
    $parser = $this->parser;
    $req = $parser->parse($inmsg);
    if (!$req) return $parser->errmsg;
    if ($req) $req = $req[0];
    $args = $this->match_pattern($req);
    if (is_string($args)) return "Failed to match bank-signed message";
    if ($args[$t->CUSTOMER] != $this->bankid) {
      return "Not signed by this bank";
    }
    $msg = $args[$t->MSG];
    $req = $parser->parse($msg);
    if (!$req) return $parser->errmsg;
    if ($req) $req = $req[0];
    return $this->match_pattern($req);
  }

  // Add $amount to the bank balance for $assetid in the main account
  // Any non-false return value is an error string
  function add_to_bank_balance($assetid, $amount) {
    global $bankid;
    global $db;

    if ($amount == 0) return;
    $key = $this->assetbalancekey($bankid, $assetid);
    $lock = $db->lock($key);
    $res = $this->add_to_bank_balance_internal($key, $assetid, $amount);
    $db->unlock($lock);
    return $res;
  }

  function add_to_bank_balance_internal($key, $assetid, $amount) {
    global $bankid;
    global $db;
    global $t;

    $balmsg = $db->get($key);
    $balargs = $this->unpack_bankmsg($balmsg, $t->ATBALANCE, $t->BALANCE);
    if (is_string($balargs) || !$balargs) {
      return "Error unpacking bank balance: '$balargs'";
    } elseif ($balargs[$t->ACCT] && $balargs[$t->ACCT] != $t->MAIN) {
      return "Bank balance message not for main account";
    } else {
      $bal = $balargs[$t->AMOUNT];
      $newbal = bcadd($bal, $amount);
      $balsign = bccomp($bal, 0);
      $newbalsign = bccomp($newbal, 0);
      if (($balsign >= 0 && $newbalsign < 0) ||
          ($balsign < 0 && $newbalsign >= 0)) {
        return "Transaction would put bank out of balance.";
      } else {
        // $t->BALANCE => array($t->BANKID,$t->TIME, $t->ASSET, $t->AMOUNT, $t->ACCT=>1)
        $msg = $this->bankmsg($t->BALANCE, $bankid, $this->gettime(), $assetid, $newbal);
        $msg = $this->bankmsg($t->ATBALANCE, $msg);
        $db->put($key, $msg);
      }
    }
    return false;
  }

  // True return is an error string
  function checkreq($args, $msg) {
    $t = $this->t;
    $db = $this->db;

    $id = $args[$t->CUSTOMER];
    $req = $args[$t->REQ];
    $reqkey = $this->acctreqkey($id);
    $res = false;
    $lock = $db->lock($reqkey);
    $oldreq = $db->get($reqkey);
    if (bccomp($req, $oldreq) <= 0) $res = "New req <= old req";
    else $db->put($reqkey, $req);
    $db->unlock($lock);
    if ($res) $res = $this->failmsg($msg, $res);
    return $res;
  }

  /*** Request processing ***/
 
  // Look up the bank's public key
  function do_bankid($t_args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    $bankid = $this->bankid;
    // $t->BANKID => array($t->PUBKEY)
    // pubkey has already been verified by $parser.
    return $db->get($t->PUBKEYSIG . "/$bankid");
  }

  // Lookup a public key
  function do_id($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    // $t->ID => array($t->BANKID,$t->ID)
    $customer = $args[$t->CUSTOMER];
    $id = $args[$t->ID];
    $key = $db->get($t->PUBKEYSIG . "/$id");
    if ($key) return $key;
    else return $this->failmsg($msg, 'No such public key');
  }

  // Register a new account
  function do_register($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    // $t->REGISTER => array($t->BANKID,$t->PUBKEY,$t->NAME=>1)
    $id = $args[$t->CUSTOMER];
    $pubkey = $args[$t->PUBKEY];
    if ($this->pubkeydb->get($id)) {
      return $this->failmsg($msg, "Already registered");
    }
    if ($this->ssl->pubkey_id($pubkey) != $id) {
      return $this->failmsg($msg, "Pubkey doesn't match ID");
    }
    if ($this->ssl->pubkey_bits($pubkey) > 4096) {
      return $this->failmsg($msg, "Key sizes larger than 4096 not allowed");
    }
    $regfee = $this->regfee;
    $tokenid = $this->tokenid;
    $success = false;
    if ($regfee > 0) {
      $inbox = $this->scaninbox($id);
      foreach ($inbox as $inmsg) {
        $inmsg_args = $this->unpack_bankmsg($inmsg, false, true);
        if (is_string($inmsg_args)) {
          return $this->failmsg($msg, "Inbox parsing failed: $inmsg_args");
        }
        if ($inmsg_args && $inmsg_args[$t->REQUEST] == $t->SPEND) {
          // $t->SPEND = array($t->BANKID,$t->TIME,$t->ID,$t->ASSET,$t->AMOUNT,$t->NOTE=>1))
          $asset = $inmsg_args[$t->ASSET];
          $amount = $inmsg_args[$t->AMOUNT];
          if ($asset == $tokenid && $amount >= $regfee) {
            $success = true;
            break;
          }
        }
      }
      if (!$success) {
        return $this->failmsg($msg, "Insufficient usage tokens for registration fee");
      }
    }
    $bankid = $this->bankid;
    $db->put($t->PUBKEY . "/$id", $pubkey);
    $res = $this->bankmsg($t->ATREGISTER, $msg);
    $db->put($t->PUBKEYSIG . "/$id", $res);
    $time = $this->gettime();
    if ($regfee != 0) {
      $spendmsg = $this->signed_spend($time, $id, $tokenid, -$regfee, "Registration fee");
      $spendmsg = $this->bankmsg($t->INBOX, $time, $spendmsg);
      $db->put($this->inboxkey($id) . "/$time", $spendmsg);
    }
    $db->put($this->accttimekey($id), 0);
    $db->put($this->acctlastkey($id), $time);
    $db->put($this->acctreqkey($id), 0);
    return $res;
  }

  // Process a getreq
  function do_getreq($args, $reqs, $msg) {
    $t = $this->t;
    $id = $args[$t->CUSTOMER];
    return $this->bankmsg($t->REQ,
                          $id,
                          $this->db->get($this->acctreqkey($id)));
  }

  // Process a time request
  function do_gettime($args, $reqs, $msg) {
    $db = $this->db;

    $err = $this->checkreq($args, $msg);
    if ($err) return $err;

    $lock = $db->lock($this->accttimekey($id));
    $res = $this->do_gettime_internal($msg, $args);
    $db->unlock($lock);
    return $res;
  }

  function do_gettime_internal($msg, $args) {
    $t = $this->t;
    $db = $this->db;

    $id = $args[$t->CUSTOMER];
    $time = $this->gettime();
    $db->put($this->accttimekey($id), $time);
    return $this->bankmsg($t->TIME, $id, $time);
  }

  function do_getfees($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;

    $err = $this->checkreq($args, $msg);
    if ($err) return $err;

    return $db->get($t->REGFEE) . "." . $db->get($t->TRANFEE);
  }

  // Process a spend
  function do_spend($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;

    $id = $args[$t->CUSTOMER];
    $lock = $db->lock($this->accttimekey($id));
    $res = $this->do_spend_internal($args, $reqs, $msg);
    $db->unlock($lock);
    return $res;
  }

  function do_spend_internal($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    $bankid = $this->bankid;
    $parser = $this->parser;

    // $t->SPEND => array($t->BANKID,$t->TIME,$t->ID,$t->ASSET,$t->AMOUNT,$t->NOTE=>1),
    $id = $args[$t->CUSTOMER];
    $time = $args[$t->TIME];
    $id2 = $args[$t->ID];
    $assetid = $args[$t->ASSET];
    $amount = $args[$t->AMOUNT];
    $note = $args[$t->NOTE];

    // Burn the transaction, even if balances don't match.
    $accttime = $this->deq_time($id, $time);
    if (!$accttime) return $this->failmsg($msg, "No timestamp enqueued");
    if ($accttime != $time) {
      return $this->failmsg($msg, "Timestamp mismatch against enqueued");
    }

    if ($id2 == $bankid) {
      return $this->failmsg($msg, "Spends to the bank are not allowed.");
    }

    if (!$this->is_asset($assetid)) {
      return $this->failmsg($msg, "Unknown asset id: $assetid");
    }
    if (!is_numeric($amount)) {
      return $this->failmsg($msg, "Not a number: $amount");
    }

    // Make sure there are no inbox entries older than the spend
    $inbox = $this->scaninbox($id);
    foreach ($inbox as $inmsg) {
      $inmsg_args = $this->unpack_bankmsg($inmsg);
      if (bccomp($inmsg_args[$t->TIME], $time) <= 0) {
        return $this->failmsg($msg, "An inbox item is older than the spend timestamp");
      }
    }

    $tokens = 0;
    $tokenid = $this->tokenid;
    $feemsg = '';
    if ($id != $id2) {
      // Spends to yourself are free
      $tokens = $this->tranfee;
    }

    $bals = array();
    if ($id != $id2) {
      // No money changes hands on spends to yourself
      $bals[$assetid] = bcsub(0, $amount);
    }
    $acctbals = array();
    $negbals = array();

    $outboxhash = false;
    $first = true;
    foreach ($reqs as $req) {
      if ($first) {
        $first = false;
        continue;
      }
      $reqargs = $this->match_pattern($req);
      if (is_string($req_args)) return $this->failmsg($msg, $reqargs); // match error
      $reqid = $reqargs[$t->CUSTOMER];
      $reqreq = $reqargs[$t->REQUEST];
      $reqtime = $reqargs[$t->TIME];
      if ($reqtime != $time) return $this->failmsg($msg, "Timestamp mismatch");
      if ($reqid != $id) return $this->failmsg($msg, "ID mismatch");
      if ($reqreq == $t->TRANFEE) {
        if ($feemsg) {
          return $this->failmsg($msg, $t->TRANFEE . ' appeared multiple times');
        }
        $tranasset = $reqargs[$t->ASSET];
        $tranamt = $reqargs[$t->AMOUNT];
        if ($tranasset != $tokenid || $tranamt != $tokens) {
          return $this->failmsg($msg, "Mismatched tranfee asset or amount");
        }
        $feemsg = $this->bankmsg($t->ATTRANFEE, $parser->get_parsemsg($req));
      } elseif ($reqreq == $t->BALANCE) {
        $balasset = $reqargs[$t->ASSET];
        $balamount = $reqargs[$t->AMOUNT];
        if (bccomp($balamount, 0) < 0) {
          $negbals[$acct][$balasset] = true;
        }
        $acct = $reqargs[$t->ACCT];
        if (!$acct) $acct = $t->MAIN;
        if (!$this->is_asset($balasset)) {
          return $this->failmsg($msg, "Unknown asset id: $balasset");
        }
        if (!is_numeric($balamount)) {
          return $this->failmsg($msg, "Not a number: $balamount");
        }
        if (!$this->is_acct_name($acct)) {
          return $this->failmsg($msg, "Acct may contain only letters and digits: $acct");
        }
        if ($acctbals[$acct][$balasset]) {
          return $this->failmsg($msg, "Duplicate acct/asset balance pair");
        }

        // Remember user's balance message, and subtract it from the total
        // for this asset.
        $acctbals[$acct][$balasset] = $parser->get_parsemsg($req);
        $bals[$balasset] = bcsub($bals[$balasset], $balamount);

        $assetbalancekey = $this->assetbalancekey($id, $balasset, $acct);
        $acctmsg = $db->get($assetbalancekey);
        if (!$acctmsg) $tokens++;
        else {
          $acctargs = $this->unpack_bankmsg($acctmsg, $t->ATBALANCE, $t->BALANCE);
          if (is_string($acctargs) || !$acctargs ||
              $acctargs[$t->ASSET] != $balasset ||
              $acctargs[$t->CUSTOMER] != $id) {
            return $this->failmsg
              ($msg, "Balance entry corrupted for acct: $acct, asset: " .
               $this->lookup_asset_name($balasset) . " - $acctmsg");
          }
          $amount = $acctargs[$t->AMOUNT];
          // Add the current balance to the total for this asset
          $bals[$balasset] = bcadd($bals[$balasset], $amount);
          if (bccomp($amount,  0) < 0) {
            if ($negbals[$acct][$balasset]) unset($negbals[$acct][$balasset]);
            else $negbals[$acct][$balasset] = true;
          }
        }
      } elseif ($reqreq == $t->OUTBOXHASH) {
        if ($outboxhashreq) {
          return $this->failmsg($msg, $t->OUTBOXHASH . " appeared multiple times");
        }
        $outboxhashmsg = $parser->get_parsemsg($req);
        $hash = $reqargs[$t->HASH];
      } else {
        return $this->failmsg($msg, "$reqreq not valid for spend. Only " .
                              $t->TRANFEE . ', ' . $t->BALANCE . ", and " .
                              $t->OUTBOXHASH);
      }
    }

    // tranfee must be included if there's a transaction fee
    if ($tokens != 0 && !$feemsg) {
      return $this->failmsg($msg, $t->TRANFEE . " missing");
    }

    // outboxhash must be included
    if (!$outboxhashmsg) {
      return $this->failmsg($msg, $t->OUTBOXHASH . " missing");
    }

    // Issuer balances must stay negative.
    // Regular balances must stay positive.
    foreach ($negbals as $negacct) {
      if (count($negacct) > 0) {
        return $this->failmsg
          ($msg, "Negative balances may not be made positive, and vice-versa");
      }
    }

    // Charge the transaction and new balance file tokens;
    $bals[$tokenid] -= $tokens;

    $errmsg = "";
    $first = true;
    // Check that the balances in the spend message, match the current balance,
    // minus amount spent minus fees.
    foreach ($bals as $balasset => $balamount) {
      if ($balamount != 0) {
        $name = $this->lookup_asset_name($balasset);
        if (!$first) $errmsg .= ', ';
        $first = false;
        $errmsg .= "$name: $balamount";
      }
    }
    if ($errmsg != '') return $this->failmsg($msg, "Balance discrepanies: $errmsg");

    $spendmsg = $parser->get_parsemsg($reqs[0]);
    $outboxhash = $this->outboxhash($id, $time, $spendmsg);
    if ($outboxhash != $hash) {
      return $this->failmsg($msg, $t->OUTBOXHASH . ' mismatch');
    }

    // All's well with the world. Commit this baby.
    $newtime = $this->gettime();
    $outbox_item = $this->bankmsg($t->ATSPEND, $spendmsg);
    if ($feemsg) $outbox_item .= ".$feemsg";
    $inbox_item = $this->bankmsg($t->INBOX, $newtime, $spendmsg);
    $res = $outbox_item;
    
    // I considered adding the transaction tokens to the bank
    // balances here, but am just leaving them in the outbox,
    // to be credited to this customer, if the spend is accepted,
    // or to the recipient, if he rejects it.
    // This means that auditing has to consider balances, outbox
    // fees, and inbox spend items.

    // Update balances
    $balancekey = $this->balancekey($id);
    foreach ($acctbals as $acct => $balances) {
      $acctdir = "$balancekey/$acct";
      foreach ($balances as $balasset => $balance) {
        $balance = $this->bankmsg($t->ATBALANCE, $balance);
        $res .= ".$balance";
        $db->put("$acctdir/$balasset", $balance);
      }
    }

    // Update outboxhash
    $outboxhash_item = $this->bankmsg($t->ATOUTBOXHASH, $outboxhashmsg);
    $res .= ".$outboxhash_item";
    $db->put($this->outboxhashkey($id), $outboxhash_item);

    if ($id != $id2) {
      // Append spend to outbox
      $db->put($this->outboxdir($id) . "/$time", $outbox_item);

      // Append spend to recipient's inbox
      $db->put($this->inboxkey($id2) . "/$newtime", $inbox_item);
    }

    // We're done
    return $res;
  }

  // Query inbox
  function do_getinbox($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;

    $err = $this->checkreq($args, $msg);
    if ($err) return $err;

    $id = $args[$t->CUSTOMER];
    $lock = $db->lock($this->accttimekey($id));
    $res = $this->do_getinbox_internal($msg, $id);
    $db->unlock($lock);
    return $res;
  }

  function do_getinbox_internal($msg, $id) {
    $t = $this->t;
    $db = $this->db;

    $inbox = $this->scaninbox($id);
    $res = $this->bankmsg($t->ATGETINBOX, $msg);
    foreach ($inbox as $inmsg) {
      $res .= '.' . $inmsg;
      $args = $this->match_message($inmsg);
      if ($args && !is_string($args)) {
        $args = $this->match_pattern($args[$t->MSG]);
      }
      if (!$args || is_string($args) ||
          $args[$t->ID] != $id) {
        return $this->failmsg($msg, "Inbox corrupt");
      }
    }
    // Append the timestamps, if there are any inbox entries
    if (count($inbox) > 0) {
      // Avoid bumping the global timestamp if the customer already
      // has two timestamps > the highest inbox timestamp.
      $time = $args[$t->TIME];
      $key = $this->accttimekey($id);
      $times = explode(',', $db->get($key));
      if (!(count($times) >= 2 &&
            bccomp($times[0], $time) > 0 &&
            bccomp($times[1], $time) > 0)) {
        $times = array($this->gettime(), $this->gettime());
        $db->put($key, implode(',', $times));
      }
      $res .= '.' . $this->bankmsg($t->GETTIME, $id, $times[0]);
      $res .= '.' . $this->bankmsg($t->GETTIME, $id, $times[1]);
    }
    return $res;
  }

  function do_processinbox($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;

    $id = $args[$t->CUSTOMER];
    $lock = $db->lock($this->accttimekey($id));
    $res = $this->do_processinbox_internal($args, $reqs, $msg);
    $db->unlock($lock);
    return $res;
  }

  function do_processinbox_internal($args, $reqs, $msg) {
    $t = $this->t;
    $db = $this->db;
    $bankid = $this->bankid;
    $parser = $this->parser;

    // $t->PROCESSINBOX => array($t->BANKID,$t->TIME,$t->TIMELIST),
    $id = $args[$t->CUSTOMER];
    $time = $args[$t->TIME];
    $timelist = $args[$t->TIMELIST];
    $times = explode('|', $timelist);

    // Burn the transaction, even if balances don't match.
    $accttime = $this->deq_time($id, $time);
    if (!$accttime) return $this->failmsg($msg, "No timestamp enqueued");
    if ($accttime != $time) {
      return $this->failmsg($msg, "Timestamp mismatch against enqueued");
    }

    $spends = array();
    $accepts = array();
    $rejects = array();

    $inboxkey = $this->inboxkey($id);
    foreach ($timelist as $inboxtime) {
      $item = $db->get("$inboxkey/$inboxtime");
      if (!$item) return $this->failmsg($msg, "Inbox entry not found: $inboxtime");
      $itemargs = $this->unpack_bankmsg($item, $t->INBOX, true);
      if ($itemargs[$t->ID] != $id) {
        return $this->failmsg($msg, "Inbox corrupt. Item found for other customer");
      }
      $request = $itemargs[$t->REQUEST];
      if ($request == $t->SPEND) $spends[$inboxtime] = $itemargs;
      elseif ($request == $t->SPENDACCEPT) $accepts[$inboxtime] = $itemargs;
      elseif ($request == $t->SPENDREJECT) $rejects[$inboxtime] = $itemargs;
      else return $this->failmsg($msg, "Inbox corrupted. Found '$request' item");
    }

    $bals = array();
    $outboxkey = $this->outboxkey($id);
    foreach ($accepts as $itemargs) {
      $spendtime = $itemargs[$time];
    }
  }

  /*** End request processing ***/

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
                        $t->SPENDACCEPT => array($t->BANKID,$t->TIME,$t->id,$t->NOTE=>1),
                        $t->SPENDREJECT => array($t->BANKID,$t->TIME,$t->id,$t->NOTE=>1),

                        // Bank signed messages
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
    $bankid = $this->bankid;
    if ($argsbankid && $bankid &&  $argsbankid != $bankid) {
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

  function commands() {
    $t = $this->t;
    if (!$this->commands) {
      $patterns = $this->patterns();
      $names = array($t->BANKID => array($t->PUBKEY),
                     $t->ID => array($t->BANKID,$t->ID),
                     $t->REGISTER => $patterns[$t->REGISTER],
                     $t->GETREQ => array($t->BANKID),
                     $t->GETTIME => array($t->BANKID,$t->REQ),
                     $t->GETFEES => array($t->BANKID,$t->REQ,$t->OPERATION=>1),
                     $t->SPEND => $patterns[$t->SPEND],
                     $t->GETINBOX => array($t->BANKID,$t->REQ),
                     $t->PROCESSINBOX => array($t->BANKID,$t->TIME,$t->TIMELIST),
                     $t->GETASSET => array($t->BANKID,$t->ASSET,$t->REQ),
                     $t->ASSET => array($t->BANKID,$t->ASSET,$t->SCALE,$t->PRECISION,$t->ASSETNAME),
                     $t->GETOUTBOX => array($t->BANKID,$t->REQ),
                     $t->GETBALANCE => array($t->BANKID,$t->REQ,$t->ACCT));
      $commands = array();
      foreach($names as $name => $pattern) {
        $commands[$name] = array("do_$name", $pattern);
      }
      $this->commands = $commands;
    }
    return $this->commands;
  }

  // Process a message and return the response
  // This is usually all you'll call from outside
  function process($msg) {
    $parser = $this->parser;
    $t = $this->t;
    $parses = $parser->parse($msg);
    if (!$parses) {
      return $this->failmsg($msg, $parser->errmsg);
    }
    $req = $parses[0][1];
    $commands = $this->commands();
    $method_pattern = $commands[$req];
    if (!$method_pattern) {
      return $this->failmsg($msg, "Unknown request: $req");
    }
    $method = $method_pattern[0];
    $pattern = array_merge(array($t->CUSTOMER,$t->REQUEST), $method_pattern[1]);
    $args = $this->parser->matchargs($parses[0], $pattern);
    if (!$args) {
      return $this->failmsg($msg,
                            "Request doesn't match pattern: " .
                            $parser->formatpattern($pattern));
    }
    $argsbankid = $args[$t->BANKID];
    if ($argsbankid &&  $argsbankid != $this->bankid) {
      return $this->failmsg($msg, "bankid mismatch");
    }
    return $this->$method($args, $parses, $msg);
  }

}

// Test code

require_once "fsdb.php";
require_once "ssl.php";

$db = new fsdb("../trubancdb");
$ssl = new ssl();
$server = new server($db, $ssl, false, 'Trubanc');

$privkey = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMwfcmkk2coTuYAEbdZ5iXggObNPzbSiDnVtndZFe4/4Xg0IQPfp
Q04OkhWIftMy1OjFhGlBzzNzdW98KYwKMgsCAwEAAQJASAgk4LPPYz84q9NkS1ZS
S6Dbm8pipga2IXxQQaf9ZZ02vWpJR0tTlxq36Zl5P+aAbMck0AvHLgiawx0qWxRz
2QIhAPwyHhCeoZ972KcRi4AIVsWtkGfQsVpVbBOzuFmtAdU9AiEAzzOwvhW6az25
MyxD5VnbEhswT+lDnGAx/WSsHlPqaOcCIQCM0ac7/Heex9Z3ozJTsVRSWNHTRhJh
sGUCs01ytUnauQIgeZrNrRHVgeEM04K0KmPtFZhNZ2jwnFM8o4m1FmuLlJsCIQDc
9tCyRjE3Zj0tXfZL2n6DGeyAc0OsfdQn6V0tFPf6hg==
-----END RSA PRIVATE KEY-----
";
$pubkey = $ssl->privkey_to_pubkey($privkey);
$id = $ssl->pubkey_id($pubkey);

$privkey2 = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAK5kvoBZ9mw6xpt7M0M383q5/mhvzLTr1HUG9kr52aJyaV7OegEQ
ndsN45klFNvzD4slOuh2blg4ca7DuuARuYUCAwEAAQJBAI+aabwrWF268HxrsMSz
OA1hRvscxMZeQ66yMvF+WBYJIE873UDxUUMgvYJ0Dz6kg6u8BFBKcxWBCIP8e2Bi
p2kCIQDaH2fPpAd477Xad+BXUiiSqOgWrEIzMiAkZsE2Q+XgYwIhAMytXoq6eZar
+id+XvcTilxSVagqkC+549Og2HtsDP73AiEAteKEVVBJbt4svY1CxG3dKVaxmd5w
oXJF/TS2HsMFmFMCICZAYGLc5sxZ565p16WlaT5HxOpgygGhZAqxDMRENUmRAiAS
H3CnJ8Ul3VWvyL5hVjFDHYnD6n18+xqsnjeSQ4bRnQ==
-----END RSA PRIVATE KEY-----
";
$pubkey2 = $ssl->privkey_to_pubkey($privkey2);
$id2 = $ssl->pubkey_id($pubkey2);

function custmsg() {
  global $id, $server, $ssl, $privkey;

  $args = func_get_args();
  $args = array_merge(array($id), $args);
  $msg = $server->utility->makemsg($args);
  $sig = $ssl->sign($msg, $privkey);
  return "$msg:\n$sig";
}

function custmsg2() {
  global $id2, $server, $ssl, $privkey2;

  $args = func_get_args();
  $args = array_merge(array($id2), $args);
  $msg = $server->utility->makemsg($args);
  $sig = $ssl->sign($msg, $privkey2);
  return "$msg:\n$sig";
}

function process($msg) {
  global $server;

  echo "\n=== Msg ===\n$msg\n";
  echo "=== Response ===\n";
  $res = $server->process($msg);
  echo $res;
  return $res;
}

// Fake a spend of tokens to the customer
$tokenid = $server->tokenid;
$t = $server->t;
$bankid = $server->bankid;
$regfee = $server->regfee;
if (!$db->get("account/$id/inbox/1") && !$db->get("pubkey/$id")) {
  $server->gettime();           // eat a transaction
  $db->put($server->inboxkey($id) . "/5",
           $server->bankmsg($t->INBOX, 5,
                            $server->signed_spend(5, $id, $tokenid, $regfee * 2, "Gift")));
  $db->put($server->inboxkey($id2) . "/5",
           $server->bankmsg($t->INBOX, 5,
                            $server->signed_spend(5, $id2, $tokenid, $regfee * 2, "Gift")));
}
$assetbalancekey = $server->assetbalancekey($id, $tokenid);
if (!$db->get($assetbalancekey)) {
  // signed_balance($time, $asset, $amount, $acct=false)
  $server->add_to_bank_balance($tokenid, -20);
  $msg = custmsg($t->BALANCE, $bankid, 2, $tokenid, 20);
  $msg = $server->bankmsg($t->ATBALANCE, $msg);
  $db->put($assetbalancekey, $msg);
}
$assetbalancekey = $server->assetbalancekey($id2, $tokenid);
if (!$db->get($assetbalancekey)) {
  // signed_balance($time, $asset, $amount, $acct=false)
  $server->add_to_bank_balance($tokenid, -20);
  $msg = custmsg2($t->BALANCE, $bankid, 2, $tokenid, 20);
  $msg = $server->bankmsg($t->ATBALANCE, $msg);
  $db->put($assetbalancekey, $msg);
}

$db->put($t->TIME, 5);

//process(custmsg('bankid',$pubkey));
//process(custmsg("register",$bankid,$pubkey,"George Jetson"));
//process(custmsg2("register",$bankid,$pubkey2,"Jane Jetson"));
//process(custmsg('id',$bankid,$id));

$msg = process(custmsg('getreq', $bankid));
$args = $server->match_message($msg);
if (is_string($args)) echo "Failure parsing or matching: $args\n";
else {
  $req = bcadd($args['req'], 1);
  //process(custmsg('gettime', $bankid, $req));
  //process(custmsg('getfees', $bankid, $req));
  process(custmsg('getinbox', $bankid, $req));
}

return;

$spend = custmsg('spend',$bankid,4,$id2,$server->tokenid,5,"Hello Big Boy!");
$fee = custmsg('tranfee',$bankid,4,$server->tokenid,2);
$bal = custmsg('balance',$bankid,4,$server->tokenid,13);
$hash = $server->outboxhash($id, 4, $spend);
$hash = custmsg('outboxhash', $bankid, 4, $hash);
$db->put($server->accttimekey($id), 4);
process("$spend.$fee.$bal.$hash");

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
