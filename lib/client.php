<?PHP

  // client.php
  // A Trubanc client API. Talks the protocol of server.php

require_once "tokens.php";
require_once "ssl.php";
require_once "utility.php";
require_once "parser.php";

class client {

  var $db;
  var $ssl;
  var $t;                       // tokens instance
  var $parser;                  // parser instance
  var $u;                       // utility instance
  var $pubkeydb;

  // Initialized by login() and newuser()
  var $id;
  var $privkey;
  var $pubkey;

  // initialized by setbank() and addbank()
  var $server;
  var $bankid;

  // Set true by getreq()
  var $syncedreq = false;

  var $unpack_reqs_key = 'unpack_reqs';

  // True to make process() print the messages it sends and receives
  var $showprocess = false;

  // Used by newsessionid()
  var $random = false;

  // $db is an object that does put(key, value), get(key), contents(key),
  // & subdir(subkey).
  // $ssl is an object that does the protocol of ssl.php
  function client($db, $ssl=false) {
    $this->db = $db;
    if (!$ssl) $ssl = new ssl();
    $this->ssl = $ssl;
    $this->t = new tokens();
    $this->pubkeydb = new pubkeydb($this, $db->subdir($this->t->PUBKEY));
    $this->parser = new parser($this->pubkeydb, $ssl);
    $this->u = new utility($this->t, $this->parser, $this);
  }

  // API Methods
  // If the return is not specified, it will be false or an error string

  // Create a new user with the given passphrase, error if already there.
  // If $privkey is a string, use that as the private key.
  // If it is an integer, default 3072, create a new private key with that many bits
  // User is logged in when this returns successfully.
  function newuser($passphrase, $privkey=3072) {
    $db = $this->db;
    $t = $this->t;
    $ssl = $this->ssl;

    $this->logout();
    $hash = $this->passphrasehash($passphrase);
    if ($db->get($t->PRIVKEY . "/$hash")) {
        return "Passphrase already has an associated private key";
    }
    if (is_numeric($privkey)) {
      $privkey = $ssl->make_privkey($privkey, $passphrase);
    }
    $privkeystr = $privkey;
    $privkey = $ssl->load_private_key($privkey, $passphrase);
    if (!$privkey) return "Could not load private key";
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    
    $id = $ssl->pubkey_id($pubkey);
    $db->put($t->PRIVKEY . "/$hash", $privkeystr);
    $db->put($this->pubkeykey($id), trim($pubkey) . "\n");

    $this->id = $id;
    $this->privkey = $privkey;
    $this->pubkey = $pubkey;
    return false;
  }

  function getprivkey($passphrase) {
    $db = $this->db;
    $t = $this->t;

    $hash = $this->passphrasehash($passphrase);
    return $db->GET($t->PRIVKEY . "/$hash");
  }

  // Log in with the given passphrase. Error if no user associated with passphrase.
  function login($passphrase) {
    $db = $this->db;
    $t = $this->t;
    $ssl = $this->ssl;

    $privkey = $this->getprivkey($passphrase);
    if (!$privkey) return "No account for passphrase in database";
    $privkey = $ssl->load_private_key($privkey, $passphrase);
    if (!$privkey) return "Could not load private key";
    $pubkey = $ssl->privkey_to_pubkey($privkey);
    $id = $ssl->pubkey_id($pubkey);

    $this->id = $id;
    $this->privkey = $privkey;
    $this->pubkey = $pubkey;
    return false;
  }

  function login_with_sessionid($sessionid) {
    $passphrase = $this->sessionpassphrase($sessionid);
    if (!$passphrase) return "No passphrase for session";
    $err = $this->login($passphrase);
    if (!$err) $this->syncedreq = true; // no server sync for session login
    return $err;
  }

  // Login, create a new session, and return either
  // an error string or an array containing the sessionid.
  function login_new_session($passphrase) {
    $res = $this->login($passphrase);
    if ($res) return $res;
    return array($this->makesession($passphrase));
  }

  function logout() {
    $ssl = $this->ssl;

    if ($this->id) $this->removesession();

    $this->id = false;
    $privkey = $this->privkey;
    if ($privkey) {
      $this->privkey = false;
      $ssl->free_privkey($privkey);
    }
    $this->bankid = false;
    $this->server = false;
  }

  // All the API methods below require the user to be logged in.
  // $id and $privkey must be set.

  // Return current user ID if logged in, otherwise false.
  function current_user() {
    return $this->privkey ? $this->id : false;
  }

  // Return pubkey of a user, default logged-in user
  function user_pubkey($id=false) {
    $db = $this->db;
    $t = $this->t;

    if (!$id) $id = $this->id;
    if ($id) return $db->get($t->pubkey . "/$id");
    return false;
  }

  function comparebanks($b1, $b2) {
    $t = $this->t;

    if ($b1[$t->NAME] < $b2[$t->NAME]) return -1;
    elseif ($b1[$t->NAME] > $b2[$t->NAME]) return 1;
    else {
      if ($b1[$t->URL] < $b2[$t->URL]) return -1;
      elseif ($b1[$t->URL] > $b2[$t->URL]) return 1;
      else return 0;
    }
  }

  // Return all the banks known by the current user:
  // array($t->BANKID => array($t->BANKID => $bankid,
  //                           $t->NAME => $name,
  //                           $t->URL => $url),
  //       ...)
  // $pubkeysig will be blank if the user has no account at the bank.
  function getbanks() {
    $t = $this->t;
    $db = $this->db;
    $id = $this->id;

    if (!$this->current_user()) return "Not logged in";

    $banks = $db->contents($t->ACCOUNT . "/$id/" . $t->BANK);
    $res = array();
    foreach ($banks as $bankid) {
      $bank = array($t->BANKID => $bankid,
                    $t->NAME => $this->bankprop($t->NAME, $bankid),
                    $t->URL => $this->bankprop($t->URL, $bankid));
      $res[] = $bank;
    }

    usort($res, array('client', 'comparebanks'));

    // Unfortunately, usort doesn't preserve keys
    $res2 = array();
    foreach ($res as $bank) {
      $res2[$bank[$t->BANKID]] = $bank;
    }

    return $res2;
  }

  // Add a bank with the given URL to the database.
  // No error, but does nothing, if the bank is already there.
  // Sets the client instance to use this bank until addbank() or setbank()
  // is called to change it.
  function addbank($url) {
    $db = $this->db;
    $t = $this->t;

    if (!$this->current_user()) return "Not logged in";

    // Hash the URL to ensure its name will work as a file name
    $urlhash = sha1($url);
    $urlkey = $t->BANK . '/' . $t->BANKID;
    $bankid = $db->get("$urlkey/$urlhash");
    if ($bankid) return $this->setbank($bankid);

    $u = $this->u;
    $id = $this->id;
    $privkey = $this->privkey;
    $pubkey = $this->pubkey;
    $ssl = $this->ssl;
    $parser = $this->parser;

    $server = $this->server;
    $nserver = new serverproxy($url, $this);
    $this->server = $nserver;
    $msg = $this->sendmsg($t->BANKID, $pubkey);
    $this->server = $server;
    $args = $u->match_message($msg);
    if (is_string($args)) return "Bank's bankid response error: $args";
    $bankid = $args[$t->CUSTOMER];
    if ($args[$t->REQUEST] != $t->REGISTER ||
        $args[$t->BANKID] != $bankid) {
      return "Bank not responding properly at $url";
    }
    $pubkey = $args[$t->PUBKEY];
    $name = $args[$t->NAME];
    if ($ssl->pubkey_id($pubkey) != $bankid) {
      return "Bank's id doesn't match its public key";
    }
    $ourl = $this->bankprop($t->URL, $bankid);
    if ($ourl) {
      if ($ourl == $url) return false;
      return "Two banks have same id: $url and $ourl";
    }
    $this->server = $nserver;

    // Initialize the bank in the database
    $this->bankid = $bankid;
    $db->put("$urlkey/$urlhash", $bankid);
    $db->put($this->bankkey($t->URL), $url);
    $db->put($this->bankkey($t->NAME), $name);
    $db->put($this->pubkeykey($bankid), trim($pubkey) . "\n");

    // Mark the user as knowing about this bank
    // Also mark this account as not yet being synced with bank
    $db->put($this->userreqkey(), -1);

    return false;
  }

  // Set the bank to the given id.
  // Sets the client instance to use this bank until addbank() or setbank()
  // is called to change it, by setting $this->bankid and $this->server
  function setbank($bankid, $check=true) {
    $db = $this->db;
    $t = $this->t;
    $u = $this->u;

    if (!$this->current_user()) return "Not logged in";

    $this->bankid = $bankid;

    $url = $this->bankprop($t->URL);
    if (!$url) return "Bank not known: $bankid";
    $server = new serverproxy($url, $this);
    $this->server = $server;

    $req = $this->userbankprop($t->REQ);
    if (!$req) {
      $db->put($this->userreqkey(), -1);
    }

    if ($check) {
      $msg = $this->sendmsg($t->BANKID, $this->pubkey);
      $args = $u->match_message($msg);
      if (is_string($args)) return "Bank's bankid response error: $args";
      if ($bankid != $args[$t->CUSTOMER]) {
        return "bankid changed since we last contacted this bank";
      }
      if ($args[$t->REQUEST] != $t->REGISTER ||
          $args[$t->BANKID] != $bankid) {
        return "Bank's bankid message wrong: $msg";
      }
    }

    return false;
  }

  // Return current bank if the user is logged in and the bank is set, else false.
  function current_bank() {
    if ($this->current_user() && $this->server) return $this->bankid;
    return false;
  }

  // All the API methods below require the user to be logged and the bank to be set.
  // Do this by calling newuser() or login(), and addbank() or setbank().
  // $this->id, $this->privkey, $this->bankid, & $this->server must be set.

  // Register at the current bank.
  // No error if already registered
  function register($name='') {
    $t = $this->t;
    $u = $this->u;
    $db = $this->db;
    $id = $this->id;
    $bankid = $this->bankid;
    $ssl = $this->ssl;

    if (!$this->current_bank()) return "In register(): Bank not set";

    // If already registered and we know it, nothing to do
    if ($db->get(userbankkey($t->PUBKEYSIG) . "/$id")) return false;

    // See if bank already knows us
    // Resist the urge to change this to a call to
    // get_pubkey_from_server. Trust me.
    $msg = $this->sendmsg($t->ID, $bankid, $id);
    $args = $this->unpack_bankmsg($msg, $t->ATREGISTER);
    if (is_string($args)) {
      // Bank doesn't know us. Register with bank.
      $msg = $this->sendmsg($t->REGISTER, $bankid, $this->pubkey($id), $name);
      $args = $this->unpack_bankmsg($msg, $t->ATREGISTER);
    }
    if (is_string($args)) return "Registration failed: $args";

    // Didn't fail. Notice registration here
    $args = $args[$t->MSG];
    if ($args[$t->CUSTOMER] != $id ||
        $args[$t->REQUEST] != $t->REGISTER ||
        $args[$t->BANKID] != $bankid) return "Malformed registration message";
    $pubkey = $args[$t->PUBKEY];
    $keyid = $ssl->pubkey_id($pubkey);
    if ($keyid != $id) return "Server's pubkey wrong";
    $db->put($this->userbankkey($t->PUBKEYSIG) . "/$id", $msg);

    return false;
  }

  // Get contacts for the current bank.
  // Contacts are sorted by nickname, name, id
  // Returns an error string or an array of items of the form:
  //
  //   array($t->ID => $id,
  //         $t->NAME => $name,
  //         $t->NICKNAME => $nickname,
  //         $t->NOTE => $note)
  function getcontacts() {
    $t = $this->t;
    $db = $this->db;

    if (!$this->current_bank()) return "In getcontacts(): Bank not set";

    $lock = $db->lock($this->userreqkey());
    $res = $this->getcontacts_internal();
    $db->unlock($lock);

    return $res;
  }

  // For usort in getcontacts_internal
  function comparecontacts($c1, $c2) {
    $t = $this->t;

    if ($c1[$t->NICKNAME] < $c2[$t->NICKNAME]) return -1;
    elseif ($c1[$t->NICKNAME] > $c2[$t->NICKNAME]) return 1;
    else {
      if ($c1[$t->NAME] < $c2[$t->NAME]) return -1;
      elseif ($c1[$t->NAME] > $c2[$t->NAME]) return 1;
      else {
        if ($c1[$t->ID] < $c2[$t->ID]) return -1;
        elseif ($c1[$t->ID] > $c2[$t->ID]) return 1;
        else return 0;
      }
    }
  }

  function getcontacts_internal() {
    $t = $this->t;
    $db = $this->db;
    
    $ids = $db->contents($this->contactkey());
    $res = array();
    foreach ($ids as $otherid) {
      $contact = $this->getcontact_internal($otherid);
      if ($contact) $res[] = $contact;
    }
    usort($res, array("client", "comparecontacts"));
    return $res;
  }

  // Get a contact, by ID.
  // Return:
  //   array($t->ID => $id,
  //         $t->NAME => $name,
  //         $t->NICKNAME => $nickname,
  //         $t->NOTE => $note)
  // or false, if can't find that contact.
  function getcontact($otherid, $add=false) {
    $t = $this->t;
    $db = $this->db;
    
    if (!$this->current_bank()) return false;

    $lock = $db->lock($this->userreqkey());
    $res = $this->getcontact_internal($otherid, $add);
    $db->unlock($lock);

    return $res;
  }

  function getcontact_internal($otherid, $add=false) {
    $t = $this->t;
    $db = $this->db;
    
    $pubkeysig = $this->contactprop($otherid, $t->PUBKEYSIG);
    if (!$pubkeysig) {
      if ($add) {
        $this->addcontact_internal($otherid);
        $pubkeysig = $this->contactprop($otherid, $t->PUBKEYSIG);
      } else {
        return $this->get_id($otherid);
      }
    }
    if (!$pubkeysig) return false;
    $res = array($t->ID => $otherid,
                 $t->NAME => $this->contactprop($otherid, $t->NAME),
                 $t->NICKNAME => $this->contactprop($otherid, $t->NICKNAME),
                 $t->NOTE => $this->contactprop($otherid, $t->NOTE));
    return $res;
  }
  
  // Add a contact to the current bank.
  // If it's already there, change its nickname and note, if included
  function addcontact($otherid, $nickname=false, $note=false) {
    $t = $this->t;
    $db = $this->db;

    $lock = $db->lock($this->userreqkey());
    $res = $this->addcontact_internal($otherid, $nickname, $note);
    $db->unlock($lock);

    return $res;
  }

  function addcontact_internal($otherid, $nickname=false, $note=false) {
    $t = $this->t;
    $db = $this->db;

    $pubkeydb = $this->pubkeydb;
    $bankid = $this->bankid;
    $ssl = $this->ssl;

    if (!$this->current_bank()) return "In addcontact(): Bank not set";

    if ($this->contactprop($otherid, $t->PUBKEYSIG)) {
      if ($nickname) $db->put($this->contactkey($otherid, $t->NICKNAME), $nickname);
      if ($note) $db->put($this->contactkey($otherid, $t->NOTE), $note);
      return false;
    }

    $msg = $this->sendmsg($t->ID, $bankid, $otherid);
    $args = $this->unpack_bankmsg($msg, $t->ATREGISTER);
    if (is_string($args)) return $args;
    $args = $args[$t->MSG];
    $pubkey = $args[$t->PUBKEY];
    $name = $args[$t->NAME];
    if ($otherid != $ssl->pubkey_id($pubkey)) {
      return "pubkey from server doesn't match ID";
    }

    if (!$nickname) $nickname = $name ? $name : 'anonymous';
    $db->put($this->contactkey($otherid, $t->NICKNAME), $nickname);
    $db->put($this->contactkey($otherid, $t->NOTE), $note);
    $db->put($this->contactkey($otherid, $t->NAME), $name);
    $db->put($this->contactkey($otherid, $t->PUBKEYSIG), $msg);
  }

  // Return the parsed ID message if an ID exists on the server,
  // or false if not.
  function get_id($id) {
    $t = $this->t;
    $db = $this->db;

    $key = $this->userbankkey($t->PUBKEYSIG) . "/$id";
    $msg = $db->get($key);
    if (!$msg) {
      $msg = $this->sendmsg($t->ID, $bankid, $id);
      $db->put($key, $msg);
    }    
    $args = $this->unpack_bankmsg($msg, $t->ATREGISTER);
    if (is_string($args)) return false;
    $pubkey = $args[$t->PUBKEY];
    if ($id != $ssl->pubkey_id($pubkey)) return false;
    return $args;
  }

  // GET sub-account names.
  // Returns an error string or an array of the sub-account names
  function getaccts() {
    $db = $this->db;

    if (!$this->current_bank()) return "In getacct(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;
    
    return $db->contents($this->userbalancekey());
  }

  // Return the assets known to the current bank.
  // array(<getassset() result>)
  function getassets() {
    $db = $this->db;
    $t = $this->t;

    $res = array();
    $bankid = $this->bankid;

    if ($bankid) {
      $assets = $db->contents($this->assetkey());
      foreach ($assets as $assetid) {
        $res[] = $this->getasset($assetid);
      }
    }

    return $res;
  }

  // Look up an asset.
  // Returns an error string or an array of items of the form:
  //
  //   array($t->ID => $issuerid,
  //         $t->ASSET => $assetid,
  //         $t->SCALE => $scale,
  //         $t->PRECISION => $precision,
  //         $t->ASSETNAME => $assetname)
  //
  // If the asset isn't found in the client database, looks it up on the
  // server, and stores it in the client database.
  function getasset($assetid) {
    $t = $this->t;
    $db = $this->db;

    if (!$this->current_bank()) return "In getacct(): Bank not set";

    $key = $this->assetkey($assetid);
    $lock = $db->lock($key, true);
    $msg = $db->get($key);
    if ($msg) {
      $db->unlock($lock);
      $args = $this->unpack_bankmsg($msg, $t->ATASSET);
      if (is_string($args)) return "While matching asset: $args";
      $args = $args[$t->MSG];
    } else {
      $args = $this->getasset_internal($assetid, $key);
      $db->unlock($lock);
      if (is_string($args)) return $args;
    }

    return array($t->ID => $args[$t->CUSTOMER],
                 $t->ASSET => $assetid,
                 $t->SCALE => $args[$t->SCALE],
                 $t->PRECISION => $args[$t->PRECISION],
                 $t->ASSETNAME => $args[$t->ASSETNAME]);
  }

  function getasset_internal($assetid, $key) {
    $t = $this->t;
    $db = $this->db;

    $bankid = $this->bankid;
    $req = $this->getreq();
    if (!$req) return "Couldn't get req for getasset";
    $msg = $this->sendmsg($t->GETASSET, $bankid, $req, $assetid);
    $args = $this->unpack_bankmsg($msg, $t->ATASSET);
    if (is_string($args)) return "While downloading asset: $args";
    $args = $args[$t->MSG];
    if ($args[$t->REQUEST] != $t->ASSET ||
        $args[$t->BANKID] != $bankid ||
        $args[$t->ASSET] != $assetid) {
      return "Bank wrapped wrong object with @asset";
    }
    $db->put($key, $msg);
    return $args;
  }

  // Look up the transaction cost.
  // Returns an error string or an array of the form:
  //
  //   array($t->TRANFEE => ARRAY(ARRAY($t->ASSET => $assetid,
  //                                    $t->AMOUNT => $amount),
  //                              ...),
  //         $t->REGFEE => ARRAY(ARRAY($t->ASSET => $assetid,
  //                                   $t->AMOUNT => $assetid),
  //                             ...),
  //         $t->FEE|<operation> => ARRAY(ARRAY($t->ASSET => $assetid,
  //                                            $t->AMOUNT => $assetid),
  //                                      ...),
  //         ...)
  //
  // Currently, only the tranfee and regfee are supported by the server,
  // and only a single fee, in usage tokens, is charged for each.
  // So that's all the spend code handles.
  //
  // If the asset isn't found in the client database, looks it up on the
  // server, and stores it in the client database.
  function getfees($reload=false) {
    $t = $this->t;
    $db = $this->db;

    if (!$this->current_bank()) return "In getfees(): Bank not set";

    $key = $this->tranfeekey();
    $lock = $db->lock($key, true);
    $msg = $db->get($key);
    if ($msg) {
      $db->unlock($lock);
      $args = $this->unpack_bankmsg($msg, $t->TRANFEE);
      if (is_string($args)) return "While matching tranfee: $args";
    } else {
      $args = $this->getfees_internal($key);
      $db->unlock($lock);
      if (is_string($args)) return $args;
    }

    $tranfee = array($t->ASSET => $args[$t->ASSET],
                     $t->AMOUNT => $args[$t->AMOUNT]);

    $msg = $this->regfee();
    if (!$msg) return "Regfee not initialized";
    $args = $this->unpack_bankmsg($msg, $t->REGFEE);
    if (is_string($args)) return "While matching regfee: $args";

    $regfee = array($t->ASSET => $args[$t->ASSET],
                    $t->AMOUNT => $args[$t->AMOUNT]);

    return array($t->TRANFEE => $tranfee,
                 $t->REGFEE => $regfee);
  }

  function getfees_internal($key) {
    $t = $this->t;
    $db = $this->db;
    $parser = $this->parser;
    $bankid = $this->bankid;

    $req = $this->getreq();
    if (!$req) return "Couldn't get req for getfees";
    $msg = $this->sendmsg($t->GETFEES, $bankid, $req);
    $reqs = $parser->parse($msg);
    if (!$reqs) return "While parsing getfees return message: " . $parser->errmsg;
    $feeargs = false;
    foreach ($reqs as $req) {
      $args = $this->match_bankreq($req);
      if (is_string($args)) return "While matching getfees return: $args";
      if ($args[$t->REQUEST] == $t->TRANFEE) {
        $db->put($key, $parser->get_parsemsg($req));
        $feeargs = $args;
      } elseif ($args[$t->REQUEST] == $t->REGFEE) {
        $db->put($this->regfeekey(), $parser->get_parsemsg($req));
      }
    }

    if (!$feeargs) $feeargs = "No tranfee from getfees request";
    return $feeargs;
  }

  // Get user balances for all sub-accounts or just one.
  // Returns an error string or an array of items of the form:
  //
  //    array($acct => array($t->ASSET =>
  //                         array($t->ASSET => $assetid,
  //                               $t->ASSETNAME => $assetname,
  //                               $t->AMOUNT => $amount,
  //                               $t->FORMATTEDAMOUNT => $formattedamount),
  //                         ...),
  //          ...)
  //
  // where $assetid & $assetname describe the asset, $amount is the
  // amount, as an integer, $formattedamount is the amount as a
  // decimal number with the scale and precision applied, and $acct
  // is the name of the sub-account(s).
  //
  // The $acct arg is true for all sub-accounts, false for the
  // $t->MAIN sub-account only, or a string for that sub-account only.
  // The $assetid arg is false for all asset or an ID for that asset only.
  //
  // If you a specific $acct and a specific $assetid, the result
  // is an array mapping property names to values, not an array of arrays.
  function getbalance($acct=true, $assetid=false) {
    $t = $this->t;
    $db = $this->db;

    if (!$this->current_bank()) return "In getbalance(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;

    $lock = $db->lock($this->userreqkey());
    $res = $this->getbalance_internal($acct, $assetid);
    $db->unlock($lock);

    return $res;
  }

  function getbalance_internal($inacct, $inassetid) {
    $t = $this->t;
    $db = $this->db;

    if (!$inacct) $inacct = $t->MAIN;
    if (is_string($inacct)) $accts = array($inacct);
    else {
      $accts = $db->contents($this->userbalancekey());
    }

    $res = array();
    foreach ($accts as $acct) {
      if ($inassetid) $assetids = array($inassetid);
      else $assetids = $db->contents($this->userbalancekey($acct));
      foreach ($assetids as $assetid) {
        $amount = $this->userbalance($acct, $assetid);
        if (!is_numeric($amount)) return "While gathering balances: $amount";
        $asset = $this->getasset($assetid);
        if (is_string($asset)) {
          $formattedamount = $amount;
          $assetname = "Unknown asset";
        } else {
          $formattedamount = $this->format_asset_value($amount, $asset);
          $assetname = $asset[$t->ASSETNAME];
        }
        $res[$acct][$assetid] = array($t->ASSET => $assetid,
                                      $t->ASSETNAME => $assetname,
                                      $t->AMOUNT => $amount,
                                      $t->FORMATTEDAMOUNT => $formattedamount);
      }
    }
    if (is_string($inacct) && $inassetid) {
      if (count($res) == 0) $res = false;
      else $res = $res[$inacct][0];
    }
    return $res;
  }

  // Initiate a spend
  // $toid is the id of the recipient of the spend
  // $assetid is the id of the asset to spend
  // $formattedamount is the formatted amount to spend
  // $acct is the source sub-account, default $t->MAIN
  function spend($toid, $assetid, $formattedamount, $acct=false, $note=false) {
    $t = $this->t;
    $db = $this->db;

    if (!$this->current_bank()) return "In spend(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;

    $lock = $db->lock($this->userreqkey());
    $res = $this->spend_internal($toid, $assetid, $formattedamount, $acct, $note);
    $db->unlock($lock);

    if ($res) {
      // Force a resync with the server.
      // Should eventually distinguish user errors, which don't require
      // resync, from errors that do.
      $this->syncedreq = false;
      $db->put($this->userbankkey($t->REQ), -2);
    }

    return $res;
  }

  function spend_internal($toid, $assetid, $formattedamount, $acct, $note) {
    $t = $this->t;
    $db = $this->db;
    $u = $this->u;

    $id = $this->id;
    $bankid = $this->bankid;
    $server = $this->server;
    $parser = $this->parser;

    if (!$acct) $acct = $t->MAIN;

    $amount = $this->unformat_asset_value($formattedamount, $assetid);
    if ($amount < 0) return "You may not spend a negative amount";

    $oldamount = $this->userbalance($acct, $assetid);
    if (!is_numeric($oldamount)) {
      return "error getting balance for asset in acct $acct: $oldamount";
    }

    $newamount = bcsub($oldamount, $amount);
    if (bccomp($oldamount, 0) >= 0 &&
        bccomp($newamount,  0) < 0) {
      return "Insufficient balance, old: $oldamount, new: $newamount";
    }

    $tranfee = false;
    $fee_balance = false;
    if ($id != $bankid) {
      $fees = $this->getfees();
      if (is_string($fees)) return $fees;
      $tranfee = $fees[$t->TRANFEE];
      $tranfee_asset = $tranfee[$t->ASSET];
      $tranfee_amt = $tranfee[$t->AMOUNT];
      if ($tranfee_asset == $assetid && $t->MAIN == $acct) {
        $newamount = bcsub($newamount, $tranfee_amt);
        if (bccomp($oldamount, 0) >= 0 &&
            bccomp($newamount, 0) < 0) {
          return "Insufficient balance for transaction fee";
        }
      } else {
        $fee_balance = $this->userbalance($t->MAIN, $tranfee_asset);
        $fee_balance = bcsub($fee_balance, $tranfee_amt);
        if (bccomp($fee_balance, 0) < 0) {
          return "Insufficient tokens for transaction fee";
        }
      }
    }

    $time = $this->gettime();
    if (!$time) return "Unable to get timestamp for transaction from bank";
    if ($note) $spend = $this->custmsg($t->SPEND, $bankid, $time, $toid,
                                       $assetid, $amount, $note);
    else $spend = $this->custmsg($t->SPEND, $bankid, $time, $toid, $assetid, $amount);
    $feeandbal = '';
    if ($tranfee) {
      $feemsg = $this->custmsg
        ($t->TRANFEE, $bankid, $time, $tranfee_asset, $tranfee_amt);
      $feeandbal = $feemsg;
      $feebal = false;
      if ($fee_balance) {
        $feebal .= $this->custmsg
          ($t->BALANCE, $bankid, $time, $tranfee_asset, $fee_balance);
        $feeandbal .= ".$feebal";
      }
    }      
    $balance = $this->custmsg
      ($t->BALANCE, $bankid, $time, $assetid, $newamount, $acct);
    $outboxhash = '';
    if ($id != $bankid) {
      $outboxhash = $this->outboxhashmsg($time, $spend);
    }

    // Compute balancehash
    if ($id != $bankid) {
      if ($feebal) {
        if ($t->MAIN == $acct) {
          $acctbals = array($acct => array($assetid => $balance,
                                           $tranfee_asset => $feebal));
        } else {
          $acctbals = array($acct => array($assetid => $balance),
                            $t->MAIN => array($tranfee_asset => $feebal));
        }
      } else {
        $acctbals = array($acct => array($assetid => $balance));
      }
      $balancehash = $this->balancehashmsg($time, $acctbals);
    }

    // Send request to server, and get response
    $msg = $spend;
    if ($feeandbal) $msg.= ".$feeandbal";
    $msg .= ".$balance";
    if ($outboxhash) $msg .= ".$outboxhash";
    if ($balancehash) $msg .= ".$balancehash";
    $msg = $server->process($msg);

    $reqs = $parser->parse($msg);
    if (!$reqs) return "Can't parse bank return from spend: $msg";
    $spendargs = $this->match_bankreq($reqs[0], $t->ATSPEND);
    if (is_string($spendargs)) {
      $args = $this->match_bankreq($reqs[0]);
      if (is_string($args)) return "Error from spend request: $args";
      $request = $args[$t->REQUEST];
      if ($request = $t->FAILED) return "Spend request failed: " . $args[$t->ERRMSG];
      return "Spend request returned unknown message type: " . $request;
    }

    $msgs = array($spend => true,
                  $balance => true);
    if ($outboxhash) $msgs[$outboxhash] = true;
    if ($balancehash) $msgs[$balancehash] = true;
    if ($feeandbal) {
      $msgs[$feemsg] = true;
      if ($feebal) $msgs[$feebal] = true;
    }

    $err = false;
    foreach ($reqs as $req) {
      $msg = $parser->get_parsemsg($req);
      $args = $this->match_bankreq($req);
      if (is_string($args)) return "Error in spend response: $args";
      $m = $args[$t->MSG];
      if (!$m) return "No wrapped message in spend return: $msg";
      $m = trim($parser->get_parsemsg($m));
      if (!$msgs[$m]) return "Returned message wasn't sent: '$m'";
      if (is_string($msgs[$m])) return "Duplicate returned message: '$m'";
      $msgs[$m] = $msg;
    }

    foreach ($msgs as $m => $msg) {
      if ($msg === true) return "Message not returned from spend: $m";
    }

    // All is well. Commit this baby.
    $db->put($this->userbalancekey($acct, $assetid), $msgs[$balance]);
    if ($outboxhash) {
      $db->put($this->useroutboxhashkey(), $msgs[$outboxhash]);
    }
    if ($balancehash) {
      $db->put($this->userbalancehashkey(), $msgs[$balancehash]);
    }
    $spend = $msgs[$spend];
    if ($feeandbal) {
      $spend = "$spend." . $msgs[$feemsg];
      if ($feebal) {
        $db->put($this->userbalancekey($t->MAIN, $tranfee_asset), $msgs[$feebal]);
      }
    }
    $db->put($this->useroutboxkey($time), $spend);

    return false;    
  }

  // Transfer from one sub-account to another
  function transfer($assetid, $formattedamount, $fromacct, $toacct) {

    if (!$this->current_bank()) return "In transfer(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;

  }

  // Get the inbox contents.
  // Returns an error string, or an array of inbox entries, indexed by
  // their timestamps:
  //
  //   array($time => array(array($t->REQUEST => $request
  //                              $t->ID => $fromid,
  //                              $t->TIME => $time,
  //                              $t->MSGTIME => $msgtime,
  //                              $t->ASSET => $assetid,
  //                              $t->ASSETNAME => $assetname,
  //                              $t->AMOUNT => $amount,
  //                              $t->FORMATTEDAMOUNT => $formattedamount,
  //                              $t->NOTE => $note),j
  //                        ...)
  //          ...)
  //
  // Where $request is $t->SPEND, $t->SPENDACCEPT, or $t->SPENDREJECT,
  // $fromid is the ID of the sender of the inbox entry,
  // $time is the timestamp from the bank on the inbox entry,
  // $msgtime is the timestamp in the sender's message,
  // $assetid & $assetname describe the asset being transferred,
  // $amount is the amount of the asset being transferred, as an integer,
  // $formattedamount is the amount as a decimal number with the scale
  // and precision applied,
  // and $NOTE is the note that came from the sender.
  // There will usually be two entries for a SPEND inbox entry, the SPEND
  // and the corresponding TRANFEE.
  // SPENDACCEPT and SPENDREJECT entries will be by themselves.
  function getinbox() {
    $db = $this->db;

    if (!$this->current_bank()) return "In getinbox(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;

    $lock = $db->lock($this->userreqkey());
    $res = $this->getinbox_internal();
    $db->unlock($lock);

    return $res;
  }

  function getinbox_internal() {
    $t = $this->t;
    $db = $this->db;
    $parser = $this->parser;

    $err = $this->sync_inbox();
    if ($err) return $err;

    $res = array();
    $key = $this->userinboxkey();
    $inbox = $db->contents($key);
    foreach ($inbox as $time) {
      $msg = $db->get("$key/$time");
      $reqs = $parser->parse($msg);
      if (!$reqs) return "Inbox parsing error: $reqs";
      $items = array();
      foreach ($reqs as $req) {
        $args = $this->match_bankreq($req);
        if (is_string($args)) return "Inbox unpack error: $args";
        if ($args[$t->TIME] != $time && $args[$t->TIME]) {
          return "Inbox message timestamp mismatch";
        }
        $args = $args[$t->MSG];
        $request = $args[$t->REQUEST];
        $item = array();
        $item[$t->REQUEST] = $request;
        $item[$t->ID] = $args[$t->CUSTOMER];
        $item[$t->TIME] = $time;
        $item[$t->MSGTIME] = $args[$t->TIME];
        $item[$t->NOTE] = $args[$t->NOTE];
        if ($request == $t->SPEND || $request = $t->TRANFEE) {
          $assetid = $args[$t->ASSET];
          $amount = $args[$t->AMOUNT];
          $asset = $this->getasset($assetid);
          $item[$t->ASSET] = $assetid;
          $item[$t->AMOUNT] = $amount;
          if (!is_string($asset)) {
            $item[$t->ASSETNAME] = $asset[$t->ASSETNAME];
            $item[$t->FORMATTEDAMOUNT] = $this->format_asset_value($amount, $asset);
          }
        } elseif ($request == $t->SPENDACCEPT || $request == $t->SPENDREJECT) {
          // Pull in data from outbox to get amounts
        } else {
          return "Bad request in inbox: $request";
        }
        $items[] = $item;
      }
      $res[$time] = $items;
    }
    return $res;
  }

  // Synchronize the current customer inbox with the current bank.
  // Return a string on error or false on success.
  // Assumes that there IS a current user and bank.
  // Does no database locking.
  function sync_inbox() {
    $t = $this->t;
    $db = $this->db;

    $bankid = $this->bankid;
    $parser = $this->parser;
    $server = $this->server;

    $req = $this->getreq();
    if (!$req) return "Couldn't get req for getinbox";
    $msg = $this->custmsg($t->GETINBOX, $bankid, $req);
    $bankmsg = $server->process($msg);
    
    $reqs = $parser->parse($bankmsg);
    if (!$reqs) return "While parsing getinbox return message: " . $parser->errmsg;
    $inbox = array();
    $times = array();
    $last_time = false;
    foreach ($reqs as $req) {
      $args = $this->match_bankreq($req);
      if (is_string($args)) return "While matching getinbox return: $args";
      $bankmsg = $parser->get_parsemsg($req);
      $request = $args[$t->REQUEST];
      if ($request == $t->ATGETINBOX) {
        $retmsg = $parser->get_parsemsg($args[$t->MSG]);
        if (trim($retmsg) != trim($msg)) return "getinbox return doesn't wrap message sent";
        $last_time = false;
      } elseif ($request == $t->INBOX) {
        $time = $args[$t->TIME];
        if ($inbox[$time]) return "getinbox return included multiple entried for time: $time";
        $inbox[$time] = $bankmsg;
        $last_time = $time;
      } elseif ($request == $t->ATTRANFEE) {
        if (!$last_time) return "In getinbox return: @tranfee not after inbox";
        $inbox[$last_time] .= ".$bankmsg";
      } elseif ($request == $t->TIME) {
        $times[] = $args[$t->TIME];
      } else {
        return "Unknown request in getinbox return: $request";
      }
    }

    $key = $this->userinboxkey();
    $keys = $db->contents($key);
    foreach ($keys as $time) {
      $inmsg = $inbox[$time];
      if ($inmsg) {
        $msg = $db->get("$key/$time");
        if ($msg != $inmsg) return "Inbox mismatch at time: $time";
        unset($inbox[$time]);
      } else {
        $db->put("$key/$time", '');
      }
    }
    foreach ($inbox as $time => $msg) {
      $db->put("$key/$time", $msg);
    }
    if (count($times) > 0) {
      $db->put($this->usertimekey(), implode(',', $times));
    }
  }

  // Process the inbox contents.
  // $directions is an array of items of the form:
  //
  //  array($t->TIME => $time,
  //        $t->REQUEST => $request,
  //        $t->NOTE => $note,
  //        $t->ACCOUNT => $acct)
  //
  // where $time is a timestamp in the inbox,
  // $request is $t->SPENDACCEPT or $t->SPENDREJECT, or omitted for
  // processing an accept or reject from a former spend recipient,
  // $note is the note to go with the accept or reject, and
  // $acct is the account into which to transfer the funds (default: main).

  function processinbox($directions) {
    $db = $this->db;

    if (!$this->current_bank()) return "In processinbox(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;

    $lock = $db->lock($this->userreqkey());
    $res = $this->processinbox_internal($directions, false);
    $db->unlock($lock);

    return $res;
  }

  function processinbox_internal($directions, $recursive) {
    $t = $this->t;
    $db = $this->db;

    $bankid = $this->bankid;
    $server = $this->server;
    $parser = $this->parser;

    $inbox = $this->getinbox_internal();
    $outbox = $this->getoutbox_internal();
    $balance = $this->getbalance_internal(true, false);

    $timelist = '';
    $deltas = array(); // array($acct => array($asset => $delta, ...), ...)
    $outbox_deletions = array(); // array($timestamp, ...)

    $msg = '';
    $msgs = array();

    foreach ($directions as $dir) {
      $time = $dir[$t->TIME];
      $request = $dir[$t->REQUEST];
      $note = $dir[$t->NOTE];
      $acct = $dir[$t->ACCT];
      if (!$acct) $acct = $t->MAIN;

      if ($timelist) $timelist .= '|';
      $timelist .= $time;

      $ins = $inbox[$time];
      if (!$ins) return "No inbox entry for time: $time";

      $in = $ins[0];
      $fee = $ins[1];        // will need generalization when I add multiple fees

      $trans = $this->gettime();

      $inreq = $in[$t->REQUEST];
      if ($inreq == $t->SPEND) {
        $id = $in[$t->ID];
        $msgtime = $in[$t->MSGTIME];
        if ($msg != '') $msg .= '.';
        if ($request == $t->SPENDACCEPT) {
          $deltas[$acct][$in[$t->ASSET]] =
            bcadd($deltas[$acct][$in[$t->ASSET]], $in[$t->AMOUNT]);
          $smsg = $this->custmsg($t->SPENDACCEPT, $bankid, $msgtime, $id, $note);
          $msgs[$smsg] = true;
          $msg .= $smsg;
        } elseif ($request == $t->SPENDREJECT) {
          if ($fee) {
            $deltas[$acct][$fee[$t->ASSET]] =
              bcadd($deltas[$acct][$fee[$t->ASSET]], $fee[$t->AMOUNT]);
          }
          $smsg = $this->custmsg($t->SPENDREJECT, $bankid, $msgtime, $id, $note);
          $msgs[$smsg] = true;
          $msg .= $smsg;
        } else {
          return "Illegal request for spend: $request";
        }
      } elseif ($inreq == $t->SPENDACCEPT || $inreq == $t->SPENDREJECT) {
        $msgtime = $in[$t->MSGTIME];
        $out = $outbox[$msgtime];
        if (!$out) return "Can't find outbox for $inreq at time $msgtime";
        $outbox_deletions[] = $msgtime;
        $outspend = $out[0];
        $outfee = $out[1];      // change when we have more than one fee
        if ($inreq == $t->SPENDREJECT) {
          // For rejected spends, we get our money back
          $deltas[$acct][$outspend[$t->ASSET]] =
            bcadd($deltas[$acct][$outspend[$t->ASSET]], $outspend[$t->AMOUNT]);
        } elseif ($outfee) {
          // For accepted spends, we get our tranfee back
          $deltas[$t->MAIN][$outfee[$t->ASSET]] =
            bcadd($deltas[$t->MAIN][$outfee[$t->ASSET]], $outfee[$t->AMOUNT]);
        }
      } else {
        return "Unrecognized inbox request: $inreq";
      }
    }

    $pmsg = $this->custmsg($t->PROCESSINBOX, $bankid, $trans, $timelist);
    $msgs[$pmsg] = true;

    if ($msg) $msg = "$pmsg.$msg";
    else $msg = $pmsg;

    $acctbals = array();

    // Create balance, outboxhash, and balancehash messages
    foreach ($deltas as $acct => $amounts) {
      foreach ($amounts as $asset => $amount) {
        $oldamount = $balance[$acct][$asset][$t->AMOUNT];
        $amount = bcadd($oldamount, $amount);
        $balmsg = $this->custmsg($t->BALANCE, $bankid, $trans, $asset, $amount, $acct);
        $msgs[$balmsg] = true;
        $acctbals[$acct][$asset] = $balmsg;
        $msg = $msg . ".$balmsg";
      }
    }

    if (count($outbox_deletions) > 0) {
      $outboxhash = $this->outboxhashmsg($trans, false, $outbox_deletions);
      $msgs[$outboxhash] = true;
      $msg = $msg . ".$outboxhash";
    } else $outboxhash = false;

    $balancehash = $this->balancehashmsg($trans, $acctbals);
    $msgs[$balancehash] = true;
    $msg = $msg . ".$balancehash";

    // Send request to server
    $msg = $server->process($msg);

    // Validate return from server
    $reqs = $parser->parse($msg);
    if (!$reqs) return "Can't parse bank return from spend: $msg";
    $args = $this->match_bankreq($reqs[0], $t->ATPROCESSINBOX);
    if (is_string($args)) {
      $args = $this->match_bankreq($reqs[0]);
      if (is_string($args)) {
        if (!$recursive) {
          // Force reload of balances and outbox
          if ($err = $this->forceinit()) return $err;
          return $this->processinbox_internal($directions, true);
        }
        return "Error from processinbox request: $args";
      }
      return "Processinbox request returned unknown message type: " . $request;
    }

    foreach ($reqs as $req) {
      $msg = $parser->get_parsemsg($req);
      $args = $this->match_bankreq($req);
      if (is_string($args)) return "Error in processinbox response: $args";
      $m = $args[$t->MSG];
      if (!$m) return "No wrapped message in processinbox return: $msg";
      $m = trim($parser->get_parsemsg($m));
      if (!$msgs[$m]) return "Returned message wasn't sent: '$m'";
      if (is_string($msgs[$m])) return "Duplicate returned message: '$m'";
      $msgs[$m] = $msg;
    }

    foreach ($msgs as $m => $msg) {
      if ($msg === true) return "Message not returned from processinbox: $m";
    }

    // Commit to database
    foreach ($acctbals as $acct => $bals) {
      foreach ($bals as $asset => $balmsg) {
        $db->put($this->userbalancekey($acct, $asset), $msgs[$balmsg]);
      }
    }

    if ($outboxhash) {
      foreach($outbox_deletions as $outbox_time) {
        $db->put($this->useroutboxkey($outbox_time), '');
      }
      $db->put($this->useroutboxhashkey(), $msgs[$outboxhash]);
    }

    $db->put($this->userbalancehashkey(), $msgs[$balancehash]);

    return false;
  }

  // Get the outbox contents.
  // Returns an error string or the outbox contents as an array of
  // of the form:
  //
  //   array($time => array(array($t->REQUEST => $request,
  //                              $t->TIME => $time,
  //                              $t->ID => $recipientid,
  //                              $t->NOTE => $note,
  //                              $t->ASSET => $assetid,
  //                              $t->ASSETNAME => $assetname,
  //                              $t->AMOUNT => $amount,
  //                              $t->FORMATTEDAMOUNT => formattedamount),
  //                        ...),
  //         ...)
  //
  // $time is the timestamp of the outbox entry
  // $request is $t->SPEND or $t->TRANFEE
  // $recipientid is the recipient for spend, or omitted for tranfee
  // $assetid is the ID of the asset transferred
  // $assetname is the name of $assetid
  // $amount is the amount transferred
  // $formattedamount is $amount formatted for output
  // $note is the transfer note, omitted for tranfee
  function getoutbox() {
    $db = $this->db;

    if (!$this->current_bank()) return "In getoutbox(): Bank not set";
    if ($err = $this->initbankaccts()) return $err;

    $lock = $db->lock($this->userreqkey());
    $res = $this->getoutbox_internal();
    $db->unlock($lock);

    return $res;
  }

  function getoutbox_internal() {
    $t = $this->t;
    $db = $this->db;
    $parser = $this->parser;

    $res = array();
    $key = $this->useroutboxkey();
    $outbox = $db->contents($key);
    foreach ($outbox as $time) {
      $msg = $db->get("$key/$time");
      $reqs = $parser->parse($msg);
      $items = array();
      if (!$reqs) return "Parse error: " . $parser->errmsg;
      foreach ($reqs as $req) {
        $args = $this->match_bankreq($req);
        if (is_string($args)) return $args;
        $args = $args[$t->MSG];
        if ($args[$t->TIME] != $time) {
          return "Outbox message timestamp mismatch";
        }
        $request = $args[$t->REQUEST];
        $item = array();
        $item[$t->REQUEST] = $request;
        $item[$t->TIME] = $time;
        if ($request == $t->SPEND) {
          $item[$t->ID] = $args[$t->ID];
          $item[$t->NOTE] = $args[$t->NOTE];
        } elseif ($request == $t->TRANFEE) {
          // Nothing special to do here
        } else {
          return "Bad request in outbox: $request";
        }
        $assetid = $args[$t->ASSET];
        $amount = $args[$t->AMOUNT];
        $asset = $this->getasset($assetid);
        $item[$t->ASSET] = $assetid;
        $item[$t->AMOUNT] = $amount;
        if (!is_string($asset)) {
          $item[$t->ASSETNAME] = $asset[$t->ASSETNAME];
          $item[$t->FORMATTEDAMOUNT] = $this->format_asset_value($amount, $asset);
        }
        $items[] = $item;
      }
      $res[$time] = $items;
    }
    return $res;
  }

  // End of API methods

  // For utility->bankgetter
  function bankid() {
    return $this->bankid;
  }

  function passphrasehash($passphrase) {
    return sha1(trim($passphrase));
  }

  // Create a signed customer message.
  // Takes an arbitrary number of args.
  function custmsg() {
    $id = $this->id;
    $u = $this->u;
    $ssl = $this->ssl;
    $privkey = $this->privkey;

    $args = func_get_args();
    $args = array_merge(array($id), $args);
    $msg = $u->makemsg($args);
    $sig = $ssl->sign($msg, $privkey);
    return trim("$msg:\n$sig");
  }

  // Send a customer message to the server.
  // Takes an arbitrary number of args.
  function sendmsg() {
    $server = $this->server;

    $req = func_get_args();
    $msg = call_user_func_array(array($this, 'custmsg'), $req);
    return $server->process($msg);
  }

  // Unpack a bank message
  // Return a string if parse error or fail from bank
  // This is called via the $unpacker arg to utility->dirhash & balancehash
  function unpack_bankmsg($msg, $request=false) {
    $parser = $this->parser;

    $reqs = $parser->parse($msg);
    if (!$reqs) return "Parse error: " . $parser->errmsg;

    $req = $reqs[0];
    $args = $this->match_bankreq($req, $request);
    if (!is_string($args)) {
      $args[$this->unpack_reqs_key] = $reqs; // save parse results
    }
    return $args;
  }

  // Unpack a bank message that has already been parsed
  function match_bankreq($req, $request=false) {
    $t = $this->t;
    $u = $this->u;
    $bankid = $this->bankid;

    $args = $u->match_pattern($req);
    if (is_string($args)) return "While matching: $args";
    if ($args[$t->CUSTOMER] != $bankid) return "Return message not from bank";
    if ($args[$t->REQUEST] == $t->FAILED) return $args[$t->ERRMSG];
    if ($request && $args[$t->REQUEST] != $request) {
      return "Wrong return type from bank: $msg";
    }
    if ($args[$t->MSG]) {
      $msgargs = $u->match_pattern($args[$t->MSG]);
      if (is_string($msgargs)) return "While matching bank-wrapped msg: $msgargs";
      if (array_key_exists($t->BANKID, $msgargs) &&
          $msgargs[$t->BANKID] != $bankid) {
        return "While matching bank-wrapped msg: bankid mismatch";
      }
      $args[$t->MSG] = $msgargs;
    }
    return $args;
  }

  function pubkey($id) {
    $db = $this->pubkeydb;
    return $db->get($id);
  }

  function pubkeykey($id) {
    $t = $this->t;
    return $t->PUBKEY . "/$id";
  }

  function bankkey($prop=false, $bankid=false) {
    $t = $this->t;
    if (!$bankid) $bankid = $this->bankid;

    $key = $t->BANK . "/$bankid";
    return $prop ? "$key/$prop" : $key;
  }

  function bankprop($prop, $bankid=false) {
    $db = $this->db;

    return $db->get($this->bankkey($prop, $bankid));
  }

  function assetkey($assetid=false) {
    $t = $this->t;

    $key = $this->bankkey($t->ASSET);
    if ($assetid) $key .= "/$assetid";
    return $key;
  }

  function assetprop($assetid) {
    $db = $this->db;

    return $db->get($this->assetkey($assetid));
  }

  function tranfeekey() {
    $t = $this->t;

    return $this->bankkey($t->TRANFEE);
  }

  function tranfee() {
    $db = $this->db;

    return $db->get($this->tranfeekey());
  }

  function regfeekey() {
    $t = $this->t;

    return $this->bankkey($t->REGFEE);
  }

  function regfee() {
    $db = $this->db;

    return $db->get($this->regfeekey());
  }

  function userbankkey($prop=false, $bankid=false) {
    $t = $this->t;
    $id = $this->id;
    if (!$bankid) $bankid = $this->bankid;

    $key = $t->ACCOUNT . "/$id/" . $t->BANK . "/$bankid";
    return $prop ? "$key/$prop" : $key;
  }

  function userbankprop($prop) {
    $db = $this->db;

    return $db->get($this->userbankkey($prop));
  }

  function userreqkey($bankid=false) {
    $t = $this->t;

    return $this->userbankkey($t->REQ, $bankid);
  }

  function userreq($bankid=false) {
    $db = $this->db;

    return $db->get($this->userreqkey($bankid));
  }

  function usertimekey() {
    $t = $this->t;

    return $this->userbankkey($t->TIME);
  }

  // Called via $unpacker->balancekey() in utility->balancehash()
  function balancekey($id) {
    if ($id != $this->id) die("ID mismatch in client->balancekey()");
    return $this->userbalancekey();
  }

  function userbalancekey($acct=false, $assetid=false) {
    $t = $this->t;

    $key = $this->userbankkey($t->BALANCE);
    if ($acct) {
      $key .= "/$acct";
      if ($assetid) $key .= "/$assetid";
    }
    return $key;
  }

  function userbalance($acct, $assetid) {
    $db = $this->db;
    $t = $this->t;

    $msg = $db->get($this->userbalancekey($acct, $assetid));
    if ($msg) {
      $args = $this->unpack_bankmsg($msg, $t->ATBALANCE);
      if (is_string($args)) return $args;
      $args = $args[$t->MSG];
      return $args[$t->AMOUNT];
    }
    return 0;
  }

  function useroutboxkey($time=false) {
    $t = $this->t;

    $key = $this->userbankkey($t->OUTBOX);
    if ($time) $key .= "/$time";
    return $key;
  }

  function useroutbox($time) {
    $db = $this->db;

    return $db->get($this->useroutboxkey($time));
  }

  function useroutboxhashkey() {
    $t = $this->t;

    return $this->userbankkey($t->OUTBOXHASH);
  }

  function useroutboxhash() {
    $db = $this->db;

    return $db->get($this->useroutboxhashkey());
  }

  function userbalancehashkey() {
    $t = $this->t;

    return $this->userbankkey($t->BALANCEHASH);
  }

  function userbalancehash() {
    $db = $this->db;

    return $db->get($this->userbalancehashkey());
  }

  function userinboxkey() {
    $db = $this->db;
    $t = $this->t;

    return $this->userbankkey($t->INBOX);
  }

  function contactkey($otherid=false, $prop=false) {
    $t = $this->t;

    $res = $this->userbankkey($t->CONTACT);
    if ($otherid) {
      $res .= "/$otherid";
      if ($prop) $res .= "/$prop";
    }
    return $res;
  }

  function contactprop($otherid, $prop) {
    $db = $this->db;

    return $db->get($this->contactkey($otherid, $prop));
  }

  // format an asset value from the asset ID or $this->getasset($assetid)
  function format_asset_value($value, $assetid) {
    $t = $this->t;

    if (is_string($assetid)) $asset = $this->getasset($assetid);
    else $asset = $assetid;
    if (is_string($asset)) return $value;
    return $this->format_value($value, $asset[$t->SCALE], $asset[$t->PRECISION]);
  }

  // Unformat an asset value from the asset ID or $this->getasset($assetid)
  function unformat_asset_value($formattedvalue, $assetid) {
    $t = $this->t;

    if (is_string($assetid)) $asset = $this->getasset($assetid);
    else $asset = $assetid;
    if (is_string($asset)) return $value;
    return $this->unformat_value($formattedvalue, $asset[$t->SCALE]);
  }

  // format an asset value for user printing
  function format_value($value, $scale, $precision) {
    $sign = 1;
    if (bccomp($value, 0) < 0) {
      $value = bcadd($value, 1);
      $sign = -1;
    }
    if ($scale == 0 && $precision == 0) $res = $value;
    else {
      if ($scale > 0) {
        $res = bcdiv($value, bcpow(10, $scale), $scale);
      }
      $dotpos = strpos($res, '.');
      if ($dotpos === false) {
        if ($precision != 0) {
          $res .= '.' . str_repeat('0', $precision);
        }
      } else {
        // Remove trailing zeroes
        for ($endpos = strlen($res)-1; $endpos>$dotpos; $endpos--) {
          if ($res[$endpos] != '0') break;
        }
        $zeroes = $precision - ($endpos - $dotpos);
        $zerostr = ($zeroes >= 0) ? str_repeat('0', $zeroes) : '';
        $res = substr($res, 0, $endpos+1) . $zerostr;
      }
    }
    if ($value == 0 && $sign < 0) $res = "-$res";
    return $res;
  }

  function unformat_value($formattedvalue, $scale) {
    if ($scale == 0) $value = $formattedvalue;
    else $value = bcmul($formattedvalue, bcpow(10, $scale), 0);
    if ((bccomp($value, 0) < 0) ||
        ($value == 0 && substr($formattedvalue, 0, 1) == '-')) {
      $value = bcsub($value, 1);
    }
    return $value;
  }

  // Send a t->ID command to the server, if there is one.
  // Parse out the pubkey, cache it in the database, and return it.
  // Return the empty string if there is no server or it doesn't know
  // the id.
  // If $wholemsg is true, return the $args for the whole $t->REGISTER
  // message, intead of just the pubkey, and return an error message,
  // instead of the empty string, if there's a problem.
  function get_pubkey_from_server($id, $wholemsg=false) {
    $t = $this->t;
    $db = $this->db;
    $bankid = $this->bankid;

    if (!$this->current_bank()) {
      return $wholemsg ? 'In get_pubkey_from_server: Bank not set' : '';
    }

    $msg = $this->sendmsg($t->ID, $bankid, $id);
    $args = $this->unpack_bankmsg($msg, $t->ATREGISTER);
    if (is_string($args)) return $wholemsg ? $args : '';
    $args = $args[$t->MSG];
    $pubkey = $args[$t->PUBKEY];
    $pubkeykey = $this->pubkeykey($id);
    if ($pubkey) {
      if (!$db->get($pubkeykey)) $db->put($pubkeykey, $pubkey);
      if ($wholemsg) return $args;
      return $pubkey;
    }
    return $wholemsg ? "Can't find pubkey on server" : '';
  }

  // Get a new request
  function getreq() {
    $t = $this->t;
    $db = $this->db;

    $key = $this->userreqkey();
    $lock = $db->lock($key);
    $reqnum = $this->getreq_internal($key);
    $db->unlock($lock);

    return $reqnum;
  }

  function getreq_internal($key) {
    $t = $this->t;
    $db = $this->db;

    $reqnum = bcadd($db->get($key), 1);
    $db->put($key, $reqnum);
    return $reqnum;
  }

  // Get a timestamp from the server
  function gettime($forcenew=false) {
    $t = $this->t;
    $db = $this->db;
    $bankid = $this->bankid;

    $key = $this->usertimekey();
    if ($forcenew) $db->put($key, '');
    else {
      $times = $db->get($key);
      if ($times) {
        $times = explode(',', $times);
        $time = $times[0];
        $db->put($key, $times[1]);
        return $time;
      }
    }

    $req = $this->getreq();
    if (!$req) return "Couldn't get req for gettime";
    $msg = $this->sendmsg($t->GETTIME, $bankid, $req);
    $args = $this->unpack_bankmsg($msg, $t->TIME);
    if (is_string($args)) return false;
    return $args[$t->TIME];
  }

  // Check once per instance that the local idea of the reqnum matches
  // that at the bank.
  // If it doesn't, clear the account information, so that initbankaccts()
  // will reinitialize.
  // Eventually, we want to compare to see if we can catch a bank error.
  function syncreq() {
    $db = $this->db;
    $t = $this->t;

    $key = $this->userbankkey($t->REQ);
    $reqnum = $db->get($key);
    if ($reqnum == -1) $this->syncedreq = true;
    if (!$this->syncedreq) {
      $bankid = $this->bankid;
      $msg = $this->sendmsg($t->GETREQ, $bankid);
      $args = $this->unpack_bankmsg($msg, $t->REQ);
      if (is_string($args)) return false;
      $newreqnum = $args[$t->REQ];
      if ($reqnum != $newreqnum) {
        $reqnum = -1;
        $balkey = $this->userbalancekey();
        $accts = $db->contents($balkey);
        foreach ($accts as $acct) {
          $acctkey = "$balkey/$acct";
          $assetids = $db->contents($acctkey);
          foreach ($assetids as $assetid) {
            $key = "$acctkey/$assetid";
            $db->put($key, '');
          }
        }
        $outboxkey = $this->useroutboxkey();
        $outtimes = $db->contents($outboxkey);
        foreach ($outtimes as $outtime) {
          $key = "$outboxkey/$outtime";
          $db->put($key, '');
        }
        $db->put($this->userbalancehashkey(), '');
        $db->put($this->useroutboxhashkey(), '');
      }
      $this->syncedreq = true;
    }
    return $reqnum;
  }

  // Force a reinit of the client database for the current user
  function forceinit() {
    $db = $this->db;

    $db->put($this->userreqkey(), 0);
    $this->syncedreq = false;
    return $this->initbankaccts();
  }

  // If we haven't yet downloaded accounts from the bank, do so now.
  // This is how a new client instance gets initialized from an existing
  // bank instance.
  // Return false on success or error string.
  function initbankaccts() {
    $t = $this->t;
    $db = $this->db;
    $id = $this->id;
    $bankid = $this->bankid;
    $parser = $this->parser;

    $reqnum = $this->syncreq();

    if ($reqnum == -1) {

      // Get $t->REQ
      $msg = $this->sendmsg($t->GETREQ, $bankid);
      $args = $this->unpack_bankmsg($msg, $t->REQ);
      if (is_string($args)) return "While getting req to initialize accounts: $args";
      $reqnum = bcadd($args[$t->REQ], 1);

      // Get account balances
      $msg = $this->sendmsg($t->GETBALANCE, $bankid, $reqnum);
      $reqs = $parser->parse($msg);
      if (!$reqs) return "While parsing getbalance: " . $parser->errmsg;
      $balances = array();
      $balancehash = false;
      foreach ($reqs as $req) {
        $args = $this->match_bankreq($req);
        if (is_string($args)) return "While matching getbalance: $args";
        $request = $args[$t->REQUEST];
        $msgargs = $args[$t->MSG];
        if ($msgargs[$t->CUSTOMER] != $id) {
          return "Bank wrapped somebody else's message: $msg";
        }
        if ($request == $t->ATBALANCE) {
          if ($msgargs[$t->REQUEST] != $t->BALANCE) {
            return "Bank wrapped a non-balance request with @balance";
          }
          $assetid = $msgargs[$t->ASSET];
          if (!$assetid) return "Bank wrapped balance missing asset ID";
          $acct = $msgargs[$t->ACCT];
          if (!$acct) $acct = $t->MAIN;
          $balances[$acct][$assetid] = $parser->get_parsemsg($req);
        } else if ($request == $t->ATBALANCEHASH) {
          $balancehash = $parser->get_parsemsg($req);
        }
      }

      // Get outbox
      $reqnum = bcadd($reqnum, 1);
      $msg = $this->sendmsg($t->GETOUTBOX, $bankid, $reqnum);
      $reqs = $parser->parse($msg);
      if (!$reqs) return "While parsing getoutbox: " . $parser->errmsg;
      $outbox = array();
      $outboxhash = '';
      foreach ($reqs as $req) {
        $args = $this->match_bankreq($req);
        if (is_string($args)) return "While matching getoutbox: $args";
        $request = $args[$t->REQUEST];
        $msgargs = $args[$t->MSG];
        if ($msgargs[$t->CUSTOMER] != $id) {
          return "Bank wrapped somebody else's message: $msg";
        }
        if ($request == $t->ATSPEND) {
          if ($msgargs[$t->REQUEST] != $t->SPEND) {
            return "Bank wrapped a non-spend request with @spend";
          }
          $time = $msgargs[$t->TIME];
          $outbox[$time] = $parser->get_parsemsg($req);
        } elseif ($request == $t->ATTRANFEE) {
          if ($msgargs[$t->REQUEST] != $t->TRANFEE) {
            return "Bank wrapped a non-tranfee request with @tranfee";
          }
          $time = $msgargs[$t->TIME];
          $msg = $outbox[$time];
          if (!$msg) return "No spend message for time: $time";
          $msg = "$msg." . $parser->get_parsemsg($req);
          $outbox[$time] = $msg;
        } elseif ($request == $t->ATOUTBOXHASH) {
          if ($msgargs[$t->REQUEST] != $t->OUTBOXHASH) {
            return "Bank wrapped a non-outbox request with @outboxhash";
          }
          $outboxhash = $parser->get_parsemsg($req);
        } elseif ($request == $t->ATGETOUTBOX) {
          // Nothing to do here          
        } else {
          return "While processing getoutbox: bad request: $request";
        }
      }

      if (count($outbox) > 0 && !$outboxhash) {
        return "While procesing getouxbox: outbox items but no outboxhash";
      }

      // All is well. Write the data
      foreach ($balances as $acct => $assets) {
        foreach ($assets as $assetid => $msg) {
          $db->put($this->userbalancekey($acct, $assetid), $msg);
        }
      }

      if ($balancehash) {
        $db->put($this->userbalancehashkey(), $balancehash);
      }

      foreach ($outbox as $time => $msg) {
        $db->put($this->useroutboxkey($time), $msg);
      }
      $db->put($this->useroutboxhashkey(), $outboxhash);
      $db->put($this->userreqkey(), $reqnum);
    }
    return false;
  }

  function balancehashmsg($time, $acctbals) {
    $u = $this->u;
    $t = $this->t;
    $db = $this->db;
    $bankid = $this->bankid;

    $hasharray = $u->balancehash($db, $this->id, $this, $acctbals);
    $hash = $hasharray[$t->HASH];
    $hashcnt = $hasharray[$t->COUNT];
    $balancehash = $this->custmsg($t->BALANCEHASH, $bankid, $time, $hashcnt, $hash);

    return $balancehash;
  }


  function outboxhashmsg($transtime, $newitem=false, $removed_times=false) {
    $db = $this->db;
    $u = $this->u;
    $t = $this->t;

    $hasharray = $u->dirhash
      ($db, $this->useroutboxkey(), $this, $newitem, $removed_times);
    $hash = $hasharray[$t->HASH];
    $hashcnt = $hasharray[$t->COUNT];
    return $this->custmsg($this->t->OUTBOXHASH,
                          $this->bankid,
                          $transtime,
                          $hashcnt,
                          $hash);
  }

  // Web client session support

  // Return a new, random, session ID
  function newsessionid() {
    $random = $this->random;
    if (!$random) {
      require_once "LoomRandom.php";
      $random = new LoomRandom();
      $this->random = $random;
    }
    $res = bin2hex($random->urandom_bytes(20));
    if (strlen($res) < 40) $res = str_repeat("0", 40 - strlen($res)) . $res;
    return $res;
  }

  // xor copies of $key with $string and return the result.
  // If $packkey is true, pack $key as a hex string first.
  // This is a really simple encryption that only really works if
  // $key is known to be random, e.g. the output of newsessionid(), and
  // $string has no known substrings.
  function xorcrypt($key, $string, $packkey=false) {
    if ($packkey) {
      $key = @pack("H*", $key);
    }
    $idx = 0;
    $keylen = strlen($key);
    $len = strlen($string);
    $res = '';
    for ($i=0; $i<$len; $i++) {
      $res .= chr(ord(substr($key, $idx, $idx+1)) ^ ord(substr($string, $i, $i+1)));
      $idx++;
      if ($idx >= $keylen) $idx = 0;
    }
    return $res;
  }

  // Return the database key for the user's session hash.
  function usersessionkey() {
    $t = $this->t;
    $id = $this->id;

    return $t->ACCOUNT . "/$id/" . $t->SESSION;
  }

  // Return the user's session hash.
  function usersessionhash() {
    $db = $this->db;

    return $db->get($this->usersessionkey());
  }

  // Return the database key for a session hash
  function sessionkey($sessionhash) {
    $t = $this->t;

    return $t->SESSION . "/$sessionhash";
  }

  // Return the passphrase corresponding to a session id
  function sessionpassphrase($sessionid) {
    $db = $this->db;

    $passcrypt = $db->get($this->sessionkey(sha1($sessionid)));
    return $this->xorcrypt($sessionid, $passcrypt, true);
  }

  // Create a new user session, encoding $passphrase with a new session id.
  // Return the new session id.
  // If the user already has a session stored with another session id,
  // remove that one first.
  function makesession($passphrase) {
    $db = $this->db;

    $sessionid = $this->newsessionid();
    $passcrypt = $this->xorcrypt($sessionid, $passphrase, true);
    $usersessionkey = $this->usersessionkey();
    $lock = $db->lock($usersessionkey);
    $oldhash = $db->get($usersessionkey);
    if ($oldhash) {
      $db->put($this->sessionkey($oldhash), '');
    }
    $newhash = sha1($sessionid);
    $db->put($this->sessionkey($newhash), $passcrypt);
    $db->put($usersessionkey, $newhash);
    $db->unlock($lock);
    return $sessionid;
  }

  // Remove the current user's session
  function removesession() {
    $db = $this->db;

    $usersessionkey = $this->usersessionkey();
    $lock = $db->lock($usersessionkey);
    $oldhash = $db->get($usersessionkey);
    if ($oldhash) {
      $db->put($this->sessionkey($oldhash), '');
      $db->put($usersessionkey, '');
    }
    $db->unlock($lock);
  }

  // Preferences
  function userpreferencekey($pref) {
    $t = $this->t;
    $id = $this->id;

    return $t->ACCOUNT . "/$id/" . $t->PREFERENCE . "/$pref";
  }

  // Get or set a user preference.
  // Include the $value to set.
  function userpreference($pref, $value=true) {
    $db = $this->db;

    $key = $this->userpreferencekey($pref);
    if ($value === true) $value = $db->get($key);
    else $db->put($key, $value);
    return $value;
  }

  // Account creation tokens
  // A kluge to keep spammers out of my web client

  function tokenkey($token=false) {
    $t = $this->t;
    
    $key = $t->TOKEN;
    if ($token) $key .= "/$token";
    return $key;
  }

  function token($token, $value=false) {
    $db = $this->db;

    $key = $this->tokenkey($token);
    if ($value === false) return $db->get($key);
    else {
      $db->put($key, $value);
      return $value;
    }
  }

  // Returns array($tok => $value, ...)
  function gettokens() {
    $db = $this->db;

    $tokens = $db->contents($this->tokenkey());
    $res = array();
    foreach ($tokens as $tok) {
      $res[$tok] = $db->get($this->tokenkey($tok));
    }
    return $res;
  }

  // Predicate. True if arg looks like an ID
  function is_id($x) {
    return is_string($x) && strlen($x) == 40 && @pack("H*", $x);
  }
}

class serverproxy {
  var $url;
  var $client;

  function serverproxy($url, $client=false) {
    if (substr($url,-1) == '/') $url = substr($url, 0, -1);
    $this->url = $url;
    $this->client = $client;
  }

  function process($msg) {
    $url = $this->url;
    $client = $this->client;

    if ($client->showprocess) echo "processing: $msg\n";
    $res = @file_get_contents("$url/?msg=" . urlencode($msg));
    if ($client->showprocess) echo "returned: $res\n";
    return $res;
  }
}

// Look up a public key, from the client database first, then from the
// current bank.
class pubkeydb {

  var $client;
  var $pubkeydb;

  var $insidep = false;

  function pubkeydb($client, $pubkeydb) {
    $this->client = $client;
    $this->pubkeydb = $pubkeydb;
  }

  function get($id) {
    $pubkeydb = $this->pubkeydb;
    $client = $this->client;

    $res = $pubkeydb->get($id);
    if ($res) return $res;

    if ($this->insidep) return "";
    $this->insidep = true;
    $res = $client->get_pubkey_from_server($id);
    $this->insidep = false;
    return $res;
  }
}

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
