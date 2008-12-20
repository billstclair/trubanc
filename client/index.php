<?php

  // client/index.php
  // A Trubanc web client

// Define $dbdir, $require_coupon
require_once "settings.php";

require_once "../lib/fsdb.php";
require_once "../lib/ssl.php";
require_once "../lib/client.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

function mqpost($x) {
  return mq($_POST[$x]);
}

function hsc($x) {
  return htmlspecialchars($x);
}

$debug = '';

function appenddebug($x) {
  global $debug;
  $debug .= $x;
}

// Add a string to the debug output.
// Does NOT add a newline.
// Use var_export($val, true) to dump arrays
function debugmsg($x) {
  global $client;

  $client->debugmsg($x);
}

$cmd = mq($_REQUEST['cmd']);

$db = new fsdb($dbdir);
$ssl = new ssl();
$client = new client($db, $ssl);
$iphone = strstr($_SERVER['HTTP_USER_AGENT'], 'iPhone');

if ($_COOKIE['debug']) $client->showprocess = 'appenddebug';

$default_menuitems = array('balance' => 'Balance',
                           'contacts' => 'Contacts',
                           'banks' => 'Banks',
                           'assets' => 'Assets',
                           //'admins' => 'Admin',
                           'logout' => 'Logout');

// Initialize (global) inputs to template.php
$title = "Trubanc Client";
$bankline = '';

$error = false;

$session = $_COOKIE['session'];
if ($session) {
  $err = $client->login_with_sessionid($session);
  if ($err) {
    setcookie('session', false);
    $error = "Session login error: $err";
    $cmd = 'logout';
    $session = false;
  } else {
    if (!$cmd) $cmd = 'balance';
  }
}

if ($client->id) {
  setbank();

  if (!$client->bankid) {
    if ($cmd && $cmd != 'logout' && $cmd != 'login' & $cmd != 'bank') {
      $cmd = 'banks';
    }
  }
} elseif ($cmd != 'login' && $cmd != 'register') $cmd = '';

if (!$cmd) draw_login();

elseif ($cmd == 'logout') do_logout();
elseif ($cmd == 'login') do_login();
elseif ($cmd == 'contact') do_contact();
elseif ($cmd == 'bank') do_bank();
elseif ($cmd == 'asset') do_asset();
elseif ($cmd == 'admin') do_admin();
elseif ($cmd == 'spend') do_spend();
elseif ($cmd == 'canceloutbox') do_canceloutbox();
elseif ($cmd == 'processinbox') do_processinbox();

elseif ($cmd == 'register') draw_register();
elseif ($cmd == 'balance') draw_balance();
elseif ($cmd == 'rawbalance') draw_raw_balance();
elseif ($cmd == 'contacts') draw_contacts();
elseif ($cmd == 'banks') draw_banks();
elseif ($cmd == 'assets') draw_assets();
elseif ($cmd == 'admins') draw_admin();
elseif ($cmd == 'coupon') draw_coupon();
elseif ($session) draw_balance();

else draw_login();

// Use $title, $body, and $onload, $debug to fill the page template.
if ($debug) $debug = "<b>=== Debug log ===</b><br/><pre>$debug</pre>\n";
include "template.php";
return;

function settitle($subtitle) {
  global $title;

  $title = "$subtitle - Trubanc Client";
}

function menuitem($cmd, $text, $highlight) {
  $res = "<a href=\"./?cmd=$cmd\">";
  if ($cmd == $highlight) $res .= '<b>';
  $res .= $text;
  if ($cmd == $highlight) $res .= '</b>';
  $res .= '</a>';
  return $res;
}

function setmenu($highlight=false, $menuitems=false) {
  global $menu, $default_menuitems;
  global $client;

  if (!$menuitems) $menuitems = $default_menuitems;

  $menu = '';
  if ($highlight && $client->bankid) {
    foreach ($menuitems as $cmd => $text) {
      if ($cmd != 'admins' ||
          ($client->bankid && $client->id == $client->bankid)) {
        if ($menu) $menu .= '&nbsp;&nbsp';
        $menu .= menuitem($cmd, $text, $highlight);
      }
    }
  } else {
    $menu .= menuitem('logout', 'Logout', false);
  }
}

function do_logout() {
  global $session, $client, $bankline, $error;

  if ($session) $client->logout();
  setcookie('session', false);
  $bankline = '';
  $error = '';
  draw_login();
}

// Here from the login page when the user presses one of the buttons
function do_login() {
  global $title, $body, $onload;
  global $keysize, $require_coupon;
  global $error;
  global $client, $ssl;

  $t = $client->t;

  $passphrase = mqpost('passphrase');
  $passphrase2 = mqpost('passphrase2');
  $coupon = mqpost('coupon');
  $name = mqpost('name');
  $keysize = mqpost('keysize');
  $login = mqpost('login');
  $newacct = mqpost('newacct');
  $showkey = mqpost('showkey');

  if ($showkey) {
    $key = $client->getprivkey($passphrase);
    if (!$key) $error = "No key for passphrase";
    draw_login($key);
  } elseif ($newacct) {
    $login = false;
    $privkey = mqpost('privkey');
    if (!$passphrase) {
      $error = "Passphrase may not be blank";
    } elseif (!$privkey && $passphrase != $passphrase2) {
      $error = "Passphrase didn't match Verification";
    } else {
      if ($privkey) {
        // Support adding a passphrase to a private key without one
        $pk = $ssl->load_private_key($privkey);
        if ($pk) {
          if ($passphrase != $passphrase2) {
            $error = "Passphrase didn't match Verification";
            draw_login();
            return;
          }
          openssl_pkey_export($pk, $privkey, $passphrase);
          openssl_free_key($pk);
        }
      } else $privkey = $keysize;

      if ($coupon) {
        if ($client->parsecoupon($coupon, $bankid, $url)) {
          $error = "Invalid coupon";
        } else {
          $error = $client->verifycoupon($coupon, $bankid, $url);
        }
      } elseif ($require_coupon) {
        $error = "Bank coupon required for registration";
      }

      if (!$error) {
        $error = $client->newuser($passphrase, $privkey);
        if (!$error) $login = true;
      }
    }
  }

  if ($login) {
    $session = $client->login_new_session($passphrase);
    if (is_string($session)) {
      $error = "Login error: $session";
    } else {
      $session = $session[0];
      if (!setcookie('session', $session)) {
        $error = "You must enable cookies to use this client";
      } else {
        if ($newacct) {
          $error = $client->addbank($coupon, $name, true);
        }
        if (!$error) {
          setbank();
          if ($client->bankid) draw_balance();
          else draw_banks();
          return;
        }
      }
    }
  }

  draw_login();
}

// Here to change banks or add a new bank
function do_bank() {
  global $client;
  global $error;

  $error = false;

  $newbank = mqpost('newbank');
  $selectbank = mqpost('selectbank');

  $bankurl = '';
  $name = '';
  if ($newbank) {
    $bankurl = trim(mqpost('bankurl'));
    $name = mqpost('name');
    $error = $client->addbank($bankurl, $name);
    if (!$error) $client->userpreference('bankid', $client->bankid);
  } elseif ($selectbank) {
    $bankid = mqpost('bank');
    if (!$bankid) $error = "You must choose a bank";
    else $client->userpreference('bankid', $bankid);
    setbank(true);
  }
  if ($error) draw_banks($bankurl, $name);
  else draw_balance();
}

function do_contact() {
  global $client;
  global $error;

  $addcontact = mqpost('addcontact');
  $deletecontacts = mqpost('deletecontacts');
  $chkcnt = mqpost('chkcnt');

  if ($addcontact) {
    $id = mqpost('id');
    $nickname = mqpost('nickname');
    $notes = mqpost('notes');
    if (!$id) {
      for ($i=0; $i<$chkcnt; $i++) {
        $chki = mqpost("chk$i");
        if ($chki) {
          $id = mqpost("id$i");
          break;
        }
      }
    }
    $err = '';
    if ($id) $err = $client->addcontact($id, $nickname, $notes);
    else $error = "You must specify an ID, either explicitly or by checking an existing contact";
    if ($err) {
      $error = "Can't add contact: $err";
      draw_contacts($id, $nickname, $notes);
    } else draw_contacts();
  } elseif ($deletecontacts) {
    for ($i=0; $i<$chkcnt; $i++) {
      $chki = mqpost("chk$i");
      if ($chki) {
        $id = mqpost("id$i");
        $client->deletecontact($id);
      }
    }
    draw_contacts();
  } else draw_balance();

  }

// Here to add a new asset
function do_asset() {
  global $client;
  global $error;

  $error = false;

  $newasset = mqpost('newasset');

  if ($newasset) {
    $scale = mqpost('scale');
    $precision = mqpost('precision');
    $assetname = mqpost('assetname');
    if (!((strlen(scale) > 0) && (strlen($precision) > 0) &&
          (strlen($assetname) > 0))) {
      $error = "Scale, Precision, and Asset name must all be specified";
    } elseif (!(is_numeric($scale) && is_numeric($precision))) {
      $error = "Scale and Precision must be numbers";
    } else {
      $error = $client->addasset($scale, $precision, $assetname);
    }
    if ($error) draw_assets($scale, $precision, $assetname);
    else draw_assets();
  } else draw_balance();
}

function do_admin() {
  global $client;

}

function do_spend() {
  global $error;
  global $client;

  $t = $client->t;
  $id = $client->id;


  $amount = mqpost('amount');
  $recipient = mqpost('recipient');
  $mintcoupon = mqpost('mintcoupon');
  $recipientid = mqpost('recipientid');
  $allowunregistered = mqpost('allowunregistered');
  $note = mqpost('note');
  $nickname = mqpost('nickname');
  $toacct = mqpost('toacct');
  $tonewacct = mqpost('tonewacct');

  $error = false;
  if (!$recipient) {
    $recipient = $recipientid;
    if ($recipient && !$allowunregistered &&
        $client->is_id($recipient) && !$client->get_id($recipient)) {
      $error = 'Recipient ID not registered at bank';
    }
  }
  if (!$recipient) {
    if ($mintcoupon) $recipient = $t->COUPON;
  } elseif ($mintcoupon) $error = "To mint a coupon don't specify a recipient";
  if (!$error) {
    if (!($amount || ($amount === '0'))) $error = 'Spend amount missing';
    elseif ($id == $recipient || !$recipient) {
      // Spend to yourself = transfer
      $recipient = $id;
      $acct2 = $toacct;
      if (!$acct2) $acct2 = $tonewacct;
      elseif ($tonewacct) $error = 'Choose "Transfer to" from the selector or by typing, but not both';
      if (!$acct2) $error = 'Recipient missing';
    } elseif ($recipient != $t->COUPON && !$client->is_id($recipient)) {
      $error = "Recipient ID malformed";
    }
  }
  if ($error) {
    draw_balance($amount, $recipient, $note, $toacct, $tonewacct);
  } else {
    // Add contact if nickname specified
    if ($nickname) {
      $client->addcontact($recipient, $nickname);
    }

    // Find the spent asset
    $found = false;
    foreach ($_POST as $key => $value) {
      $prefix = 'spentasset';
      $prelen = strlen($prefix);
      if (substr($key, 0, $prelen) == $prefix) {
        $acctdotasset = substr($key, $prelen);
        $acctdotasset = explode('|', $acctdotasset);
        if (count($acctdotasset) != 2) {
          $error = "Bug: don't understand spentasset";
          draw_balance($amount, $recipient, $note, $toacct, $tonewacct);
        } else {
          $acctidx = $acctdotasset[0];
          $assetidx = $acctdotasset[1];
          $acct = mqpost("acct$acctidx");
          $assetid = mqpost("assetid$acctidx|$assetidx");
          if (!$acct || !$assetid) {
            $error = "Bug: blank acct or assetid";
            draw_balance($amount, $recipient, $note, $toacct, $tonewacct);
          } else {
            if ($acct2) $acct = array($acct, $acct2);
            $error = $client->spend($recipient, $assetid, $amount, $acct, $note);
            if ($error) {
              draw_balance($amount, $recipient, $note, $toacct, $tonewacct);
            } elseif ($mintcoupon) {
              draw_coupon($client->lastspendtime);
            } else {
              draw_balance();
            }
          }
        }
        $found = true;
        break;
      }
    }
    if (!$found) {
      $error = "Bug: can't find acct/asset to spend";
      draw_balance($amount, $recipient, $note, $toacct, $tonewacct);
    }
  }
}

function do_canceloutbox() {
  global $error;
  global $client;

  $cancelcount = mqpost('cancelcount');
  for ($i=0; $i<$cancelcount; $i++) {
    if (mqpost("cancel$i")) {
      $canceltime = mqpost("canceltime$i");
      $error = $client->spendreject($canceltime, "Spend cancelled");
      draw_balance();
      break;
    }
  }
}

function do_processinbox() {
  global $error;
  global $client;
 
  $t = $client->t;

  $spendcnt = mqpost('spendcnt');
  $nonspendcnt = mqpost('nonspendcnt');

  $directions = array();
  for ($i=0; $i<$spendcnt; $i++) {
    $time = mqpost("spendtime$i");
    $spend = mqpost("spend$i");
    $note = mqpost("spendnote$i");
    $acct = mqpost("acct$i");
    if ($spend == 'accept' || $spend == 'reject') {
      $dir = array($t->TIME => $time);
      if ($note) $dir[$t->NOTE] = $note;
      $dir[$t->REQUEST] = ($spend == 'accept') ? $t->SPENDACCEPT : $t->SPENDREJECT;
      if ($acct) $dir[$t->ACCT] = $acct;
      $directions[] = $dir;
    }
    $nickname = mqpost("spendnick$i");
    $spendid = mqpost("spendid$i");
    if ($nickname && $spendid) {
      $client->addcontact($spendid, $nickname);
    }
  }

  for ($i=0; $i<$nonspendcnt; $i++) {
    $time = mqpost("nonspendtime$i");
    $process = mqpost("nonspend$i");
    if ($process) {
      $dir = array($t->TIME => $time);
      $directions[] = $dir;
    }
    $nickname = mqpost("nonspendnick$i");
    $spendid = mqpost("nonspendid$i");
    if ($nickname && $spendid) {
      $client->addcontact($spendid, $nickname);
    }
  }

  if (count($directions) > 0) {
    $err = $client->processinbox($directions);
    if ($err) $error = "error from processinbox: $err";
  }

  draw_balance();
}

function draw_login($key=false) {
  global $title, $menu, $body, $onload;
  global $error;

  $page = mqpost('page');
  if ($page == 'register') return draw_register($key);

  $menu = '';
  $onload = "document.forms[0].passphrase.focus()";
  $body = <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="login"/>
<table>
<tr>
<td><b>Passphrase:</b></td>
<td><input type="password" name="passphrase" size="50"/>
<input type="submit" name="login" value="Login"/></td>
</tr><tr>
<td></td>
<td style="color: red">$error&nbsp;</td>
</tr>
</table>
<a href="./?cmd=register">Register a new account</a>
</form>

EOT;
}

function draw_register($key=false) {

  global $title, $menu, $body, $onload;
  global $keysize, $require_tokens;
  global $error;

  $key = hsc($key);

  settitle('Register');
  $menu = '';
  $onload = "document.forms[0].passphrase.focus()";

  if (!$keysize) $keysize = 3072;
  $sel = ' selected="selected"';
  $sel512 = ($keysize == 512) ? $sel : '';
  $sel1024 = ($keysize == 1024) ? $sel : '';
  $sel2048 = ($keysize == 2048) ? $sel : '';
  $sel3072 = ($keysize == 3072) ? $sel : '';
  $sel4096 = ($keysize == 4096) ? $sel : '';

  $body = <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="login"/>
<table>
<tr>
<td><b>Passphrase:</b></td>
<td><input type="password" name="passphrase" size="50"/>
<input type="submit" name="login" value="Login"/></td>
<input type="hidden" name="page" value="register"/>
</tr><tr>
<td></td>
<td style="color: red">$error&nbsp;</td>
</tr><tr>
<td><b>Verification:</b></td>
<td><input type="password" name="passphrase2" size="50"/>
</tr><tr>
<td><b>Coupon:</b></td>
<td><textarea name="coupon" cols="40" rows="2"></textarea></td>
</tr><tr>
<td><b>Account Name<br/>(Optional):</b></td>
<td><input type="text" name="name" size="40"/></td>
</tr><tr>
<td><b>Key size:</b></td>
<td>
<select name="keysize">
<option value="512"$sel512>512</option>
<option value="1024"$sel1024>1024</option>
<option value="2048"$sel2048>2048</option>
<option value="3072"$sel3072>3072</option>
<option value="4096"$sel4096>4096</option>
</select>
<input type="submit" name="newacct" value="Create account"/>
<input type="submit" name="showkey" value="Show key"/></td>
</tr><tr>
<td></td>
<td>
To generate a new private key, leave the area below blank, enter a
passphrase, the passphrase again to verify, a bank coupon, an optional
account name, a key size, and click the "Create account" button. To
use an existing private key, paste the private key below, enter its
passphrase above, a bank coupon, an optional account name, and click
the "Create account" button.  To show your encrypted private key,
enter its passphrase, and click the "Show key" button. Warning: if you
forget your passphrase, <b>nobody can recover it, ever</b>.
</td>
</tr><tr>
<td></td>
<td><textarea name="privkey" cols="64" rows="42">$key</textarea></td>
</table>

EOT;
}

function bankline() {
  global $client;
  
  $t = $client->t;
  $bankid = $client->bankid;

  $bankline = '';
  if ($bankid) {
    $bank = $client->getbank($bankid);

    if ($bank) {
      $name = $bank[$t->NAME];
      $url = $bank[$t->URL];
      $bankline = "<b>Bank:</b> $name <a href=\"$url\">$url</a><br/>\n";
    }
  }
  return $bankline;
}

function idcode() {
  global $client;

  $id = '';
  if ($client) $id = $client->id;
  if (!$id) return '';
  $args = $client->get_id($id);
  if ($args) {
    $t = $client->t;
    $name = $args[$t->NAME];
    if ($name) $res = "<b>Account name:</b> $name<br/>\n";
  }
  $res .= "<b>Your ID:</b> $id<br/>\n";
  return $res;
}

function setbank($reporterror=false) {
  global $banks, $bank;
  global $error;
  global $client;

  $t = $client->t;

  $banks = $client->getbanks();
  $bank = false;
  $bankid = $client->userpreference('bankid');
  if ($bankid) {
    $err = $client->setbank($bankid, false);
    if ($err) {
      $err = "Can't set bank: $err";
      $client->userpreference('bankid', '');
      $bankid = false;
    }
  }
  if (!$bankid) {
    foreach ($banks as $bank) {
      $bankid = $bank[$t->BANKID];
      $err = $client->setbank($bankid);
      if ($err) {
        $err = "Can't set bank: $err";
        $bankid = false;
      }
      else {
        $client->userpreference('bankid', $bankid);
        break;
      }
    } 
    if (!$bankid) {
      $err = "No known banks. Please add one.";
    }
  }

  if ($reporterror) $error = $err;
}

function namestr($nickname, $name, $id) {
 if ($nickname) {
    if ($name) {
      if ($name != $nickname) $namestr = "$nickname ($name)";
      else $namestr = $name;
    } else $namestr = $nickname;
  } elseif ($name) $namestr = "($name)";
  else $namestr = "$id";
  return "$namestr";
}

function contact_namestr($contact) {
  global $client;

  $t = $client->t;

  $nickname = hsc($contact[$t->NICKNAME]);
  $name = hsc($contact[$t->NAME]);
  $recipid = hsc($contact[$t->ID]);
  return namestr($nickname, $name, $recipid);
}

function draw_balance($spend_amount=false, $recipient=false, $note=false,
                      $toacct=false, $tonewacct=false) {
  global $client;
  global $error;
  global $onload, $body;
  global $iphone;
  
  $t = $client->t;

  $bankid = $client->bankid();
  $banks = $client->getbanks();

  settitle('Balance');
  setmenu('balance');

  $saveerror = $error;
  $error = false;

  $bankopts = '';
  foreach ($banks as $bid => $b) {
    if ($bid != $bankid) {
      if ($client->userreq($bid) != -1) {
        $bname = $b[$t->NAME];
        $burl = $b[$t->URL];
        $bankopts = "<option value=\"$bid\">$bname $burl</option>\n";
      }
    }
  }

  if ($bankopts) {
    $bankcode .= <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="bank">
<select name="bank">
<option value="">Choose a bank...</option>
$bankopts
</select>
<input type="submit" name="selectbank" value="Change Bank"/>
</form>

EOT;
  }

  $inboxcode = '';
  $balcode = '';
  $assetlist = '';
  $assetidx = 0;
  $acctidx = 0;
  $gotbal = false;
  $contacts = $client->getcontacts();
  $havecontacts = (count($contacts) > 0);

  if (!$error && $client->bankid) {
    // Print inbox, if there is one
    $inbox = $client->getinbox();
    $outbox = $client->getoutbox();
    $accts = $client->getaccts();

    $acctoptions = '';
    if (count($accts) > 1) {
      $first = true;
      foreach ($accts as $acct) {
        $acct = hsc($acct);
        $acctoptions .= <<<EOT
          <option value="$acct">$acct</option>

EOT;
      }
    }

    if (is_string($inbox)) $error = "Error getting inbox: $inbox";
    elseif (count($inbox) == 0) $inboxcode .= "<b>=== Inbox empty ===</b><br/><br/>\n";
    else {
      if ($acctoptions) $acctheader = "\n<th>To Acct</th>";

      $inboxcode .= <<<EOT
<table border="1">
<caption><b>=== Inbox ===</b></caption>
<tr>
<th>Request</th>
<th>From</th>
<th colspan="2">Amount</th>
<th>Note</th>
<th>Action</th>
<th>Reply</th>$acctheader
</tr>

EOT;
      $seloptions = <<<EOT
<option value="accept">Accept</option>
<option value="reject">Reject</option>
<option value="ignore">Ignore</option>

EOT;

      if (is_string($outbox)) {
        $error = "Error getting outbox: $outbox";
        $outbox = array();
      }
      $nonspends = array();
      $spendcnt = 0;
      $assets = $client->getassets();
      foreach ($inbox as $itemkey => $item) {
        $item = $item[0];
        $request = $item[$t->REQUEST];
        $fromid = $item[$t->ID];
        $time = $item[$t->TIME];
        $contact = $client->getcontact($fromid);
        if ($contact) {
          $namestr = contact_namestr($contact);
          if ($namestr != $fromid) {
            $namestr = "<span title=\"$fromid\">$namestr</span>";
          }
        } else $namestr = hsc($fromid);

        if ($request != $t->SPEND) {
          $msgtime = $item[$t->MSGTIME];
          $outitem = $outbox[$msgtime];
          // outbox entries are array($spend, $tranfee)
          if ($outitem) $outitem = $outitem[0];
          if ($outitem) {
            $item[$t->ASSETNAME] = $outitem[$t->ASSETNAME];
            $item[$t->FORMATTEDAMOUNT] = $outitem[$t->FORMATTEDAMOUNT];
            $item['reply'] = $item[$t->NOTE];
            $item[$t->NOTE] = $outitem[$t->NOTE];
          }
          $nonspends[] = $item;
        }
        else {
          $assetid = $item[$t->ASSET];
          $assetname = hsc($item[$t->ASSETNAME]);
          if (!$assets[$assetid]) {
            $assetname .= ' <span style="color: red;"><i>(new)</i></span>';
          }
          $amount = hsc($item[$t->FORMATTEDAMOUNT]);
          $itemnote = hsc($item[$t->NOTE]);
          if (!$itemnote) $itemnote = '&nbsp;';
          else $itemnote = str_replace("\n", "<br/>\n", $itemnote);
          $selname = "spend$spendcnt";
          $notename = "spendnote$spendcnt";
          $acctselname = "acct$spendcnt";
          if (!$contact[$t->CONTACT]) {
            $namestr .= <<<EOT
<br/>
<input type="hidden" name="spendid$spendcnt" value="$fromid"/>
Nickname:
<input type="text" name="spendnick$spendcnt" size="10"/>
EOT;
          }
          $timecode = <<<EOT
<input type="hidden" name="spendtime$spendcnt" value="$time">
EOT;

          $spendcnt++;
          $selcode = <<<EOT
<select name="$selname">
$seloptions
</select>

EOT;
          if ($acctoptions) {
            $acctcode = <<<EOT
<td><select name="$acctselname">
$acctoptions
</select></td>
EOT;
          }
          $inboxcode .= <<<EOT
$timecode
<tr>
<td>Spend</td>
<td>$namestr</td>
<td align="right" style="border-right-width: 0;">$amount</td>
<td style="border-left-width: 0;">$assetname</td>
<td>$itemnote</td>
<td>$selcode</td>
<td><textarea name="$notename" cols="20" rows="2"></textarea></td>
$acctcode
</tr>

EOT;
        }
      }
      $nonspendcnt = 0;
      foreach ($nonspends as $item) {
        $request = $item[$t->REQUEST];
        $fromid = $item[$t->ID];
        $reqstr = ($request == $t->SPENDACCEPT) ? "Accept" : "Reject";
        $time = $item[$t->TIME];
        $contact = $client->getcontact($fromid);
        if ($contact) {
          $namestr = contact_namestr($contact);
          if ($namestr != $fromid) {
            $namestr = "<span title=\"$fromid\">$namestr</span>";
          }
        } else $namestr = hsc($fromid);
        $assetname = hsc($item[$t->ASSETNAME]);
        $amount = hsc($item[$t->FORMATTEDAMOUNT]);
        $itemnote = hsc($item[$t->NOTE]);
        if (!$itemnote) $itemnote = '&nbsp;';
        else $itemnote = $itemnote = str_replace("\n", "<br/>\n", $itemnote);
        $reply = hsc($item['reply']);
        if (!$reply) $reply = '&nbsp;';
        else $reply = str_replace("\n", "<br/>\n", $reply);
        $selname = "nonspend$nonspendcnt";
        if (!$contact[$t->CONTACT]) {
          $namestr .= <<<EOT
<br/>
<input type="hidden" name="nonspendid$nonspendcnt" value="$fromid"/>
Nickname:
<input type="text" name="nonspendnick$nonspendcnt" size="10"/>
EOT;
          }
        $timecode = <<<EOT
<input type="hidden" name="nonspendtime$nonspendcnt" value="$time">
EOT;
        $nonspendcnt++;
        $selcode = <<<EOT
<input type="checkbox" name="$selname" checked="checked">Remove</input>

EOT;
          $inboxcode .= <<<EOT
$timecode
<tr>
<td>$reqstr</td>
<td>$namestr</td>
<td align="right" style="border-right-width: 0;">$amount</td>
<td style="border-left-width: 0;">$assetname</td>
<td>$itemnote</td>
<td>$selcode</td>
<td>$reply</td>
<td>&nbsp;</td>
</tr>

EOT;
      }
      
      $inboxcode = <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="processinbox"/>
<input type="hidden" name="spendcnt" value="$spendcnt"/>
<input type="hidden" name="nonspendcnt" value="$nonspendcnt"/>
$inboxcode
</table>
<br/>
<input type="submit" name="submit" value="Process Inbox"/>
</form>

EOT;
    }

    // Index the spends in the inbox by MSGTIME
    $inboxspends = array();
    foreach ($inbox as $items) {
      $item = $items[0];
      $request = $item[$t->REQUEST];
      $inboxspends[$item[$t->MSGTIME]] = $item;
    }

    // Prepare outbox display
    $cancelcount = 0;
    $outboxcode = '';
    foreach ($outbox as $time => $items) {
      $timestr = hsc($time);
      foreach ($items as $item) {
        $request = $item[$t->REQUEST];
        if ($request == $t->SPEND) {
          $recip = $item[$t->ID];
          if (!$outboxcode) $outboxcode = <<<EOT
<table border="1">
<caption><b>=== Outbox ===</b></caption>
<tr>
<th>Time</th>
<th>Recipient</th>
<th colspan="2">Amount</th>
<th>Note</th>
<th>Action</th>
</tr>
EOT;
          $assetname = hsc($item[$t->ASSETNAME]);
          $amount = hsc($item[$t->FORMATTEDAMOUNT]);
          $not = hsc($item[$t->NOTE]);
          if (!$not) $not = '&nbsp;';
          if ($recip == $t->COUPON) {
            $recip = hsc($recip);
            $timearg = urlencode($time);
            $namestr = <<<EOT
<a href="./?cmd=coupon&time=$timearg">$recip</a>
EOT;
          } else {
            $contact = $client->getcontact($recip);
            if ($contact) {
              $namestr = contact_namestr($contact);
              if ($namestr != $recipient) {
                $namestr = "<span title=\"$recipient\">$namestr<span>";
              }
            } else $namestr = hsc($recip);
          }
          $cancelcode = '&nbsp;';
          if (!$inboxspends[$time]) {
            $cancelcode = <<<EOT
<input type="hidden" name="canceltime$cancelcount" value="$timestr"/>
<input type="submit" name="cancel$cancelcount" value="Cancel"/>

EOT;
            $cancelcount++;
          }
          $outboxcode .= <<<EOT
<tr>
<td>$timestr</td>
<td>$namestr</td>
<td align="right" style="border-right-width: 0;">$amount</td>
<td style="border-left-width: 0;">$assetname</td>
<td>$not</td>
<td>$cancelcode</td>
</tr>
EOT;
        }
      }
    }
    if ($outboxcode) {
      $outboxcode .= "</table>\n";
      if ($cancelcount > 0) {
        $outboxcode = <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="canceloutbox"/>
<input type="hidden" name="cancelcount" value="$cancelcount"/>
$outboxcode
</form>

EOT;
      }
    }

    $balance = $client->getbalance();
    if (is_string($balance)) $error = $balance;
    elseif (count($balance) > 0) {
      $balcode = "<table border=\"1\">\n<caption><b>=== Balances ===</b></caption>
<tr><td><table>";
      $firstacct = true;
      foreach ($balance as $acct => $assets) {
        $acct = hsc($acct);
        $assetcode = '';
        $newassetlist = '';
        foreach ($assets as $asset => $data) {
          if ($data[$t->AMOUNT] != 0) {
            $gotbal = true;
            $assetid = hsc($data[$t->ASSET]);
            $assetname = hsc($data[$t->ASSETNAME]);
            $formattedamount = hsc($data[$t->FORMATTEDAMOUNT]);
            $submitcode = '';
            $newassetlist .= <<<EOT
<input type="hidden" name="assetid$acctidx|$assetidx" value="$assetid"/>

EOT;
            $submitcode = <<<EOT
<input type="submit" name="spentasset$acctidx|$assetidx" value="Spend"/>

EOT;
            $assetidx++;
            $assetcode .= <<<EOT
<tr>
<td align="right"><span style="margin-right: 5px">$formattedamount</span></td>
<td>$assetname</td>
<td>$submitcode</td>
</tr>

EOT;
          }
        }

        if ($assetcode) {
          if (!$firstacct) {
            $balcode .= "<tr><td colspan=\"3\">&nbsp;</td></tr>\n";
          } else $firstacct = false;
          $balcode .= "<tr><th colspan=\"3\">- $acct -</th></tr>\n$assetcode";
        }

        if ($newassetlist) {
          $assetlist .= <<<EOT
<input type="hidden" name="acct$acctidx" value="$acct"/>
$newassetlist
EOT;
          $acctidx++;
        }
      }
      $balcode .= "</table>\n</td></tr></table>\n";
      $balcode .= '<br/><a href="./?cmd=rawbalance">Show raw balance</a><br/>' . "\n";
    }

    $spendcode = '';
    $closespend = '';
    if ($gotbal) {
      $recipopts = '<select name="recipient">
<option value="">Choose contact...</option>
';
      $found = false;
      foreach ($contacts as $contact) {
        $namestr = contact_namestr($contact);
        $recipid = $contact[$t->ID];
        $selected = '';
        if ($recipid == $recipient) {
          $selected = ' selected="selected"';
          $found = true;
        }
        $recipopts .= <<<EOT
<option value="$recipid"$selected>$namestr</option>

EOT;
      }
      $recipopts .= "</select>\n";
      $selectmint = '';
      if ($recipient == $t->COUPON) $selectmint = ' checked="checked"';
      $recipientid = '';
      if (!$found && $recipient != $t->COUPON) $recipientid = $recipient;
      $openspend = '<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="spend"/>

';
      $acctoptions = '';
      if (count($accts) > 1) {
        $first = true;
        foreach ($accts as $acct) {
          $selcode = '';
          if ($acct == $toacct) $selcode = ' selected="selected"';
          $acct = hsc($acct);
          $acctoptions .= <<<EOT
<option value="$acct"$selcode>$acct</option>

EOT;
        }
      }
      $acctcode = '';
      if ($acctoptions) {
        $acctcode = <<<EOT

<td><select name="toacct">
<option value="">Select or fill-in below...</option>
$acctoptions
</select></td>
</tr>
<tr>
<td><b>&nbsp;</b></td>

EOT;
      }

      $spendcode = <<<EOT

<table>
<tr>
<td><b>Spend amount:</b></td>
<td><input type="text" name="amount" size="20" value="$spend_amount" style="text-align: right;"/>
</tr><tr>
<td><b>Recipient:</b></td>
<td>$recipopts
<input type="checkbox" name="mintcoupon"$selectmint>Mint coupon</input></td>
</tr><tr>
<td><b>Note:</b></td>
<td><textarea name="note" cols="40" rows="10">$note</textarea></td>
</tr><tr>
<td><b>Recipient ID:</b></td>
<td><input type="text" name="recipientid" size="40" value="$recipientid"/>
<input type="checkbox" name="allowunregistered">Allow unregistered</input></td>
</tr><tr>
<td><b>Nickname:</b></td>
<td><input type="text" name="nickname" size="30" value="$nickname"/></td>
<tr>
<td><b>Transfer to:</b></td>$acctcode
<td><input type="text" name="tonewacct" size="30" value="$tonewacct"/></td>
</tr>
</table>
EOT;
      $onload = "document.forms[0].amount.focus()";
      $closespend = "</form>\n";
      $instructions = <<<EOT
<p>
To make a spend, fill in the "Spend amount", choose a "Recipient" or
enter a "Recipient ID, enter (optionally) a "Note", and click the
"Spend" button next to the asset you wish to spend.
</p>
<p>
To transfer balances, enter the "Spend Amount", select or fill-in the
"Transfer to" name (letters, numbers, and spaces only), and click
the"Spend" button next to the asset you want to transfer from. Each
storage location costs one usage token, and there is currently no way
to recover an unused location. 0 balances will show only on the raw
balance screen.
</p>
<p>
To mint a coupon, enter the "Spend Amount", check the "Mint coupon"
box, and click the "Spend" button next to the asset you want to
transfer to the coupon. You can redeem a coupon on the "Banks" page.
</p>
<p>
Entering a "Nickname" will add the "Recipient ID" to your contacts
list with that nickname, or change the nickname of the selected
"Recipient".
</p>

EOT;
    }
  }

  if ($saveerror) {
    if ($error) $error = "$saveerror<br/>$error";
    else $error = $saveerror;
  }
  if ($error) {
    $error = "<span style=\"color: red\";\">$error</span>\n";
  }
  $fullspend = <<<EOT
$openspend
<table>
<tr>
<td valign="top">
$assetlist$balcode
</td>

EOT;
  if ($iphone) $fullspend .= "</tr>\n<tr>\n";
  $fullspend .= <<<EOT
<td valign="top">
$spendcode
</td>
</table>
$closespend
EOT;
  $body = "$error<br/>$bankcode$inboxcode$fullspend$outboxcode$instructions";
}

function draw_coupon($time = false) {
  global $client;
  global $error;
  global $onload, $body;
  
  $t = $client->t;

  settitle('Coupon');
  setmenu('balance');

  $outbox = $client->getoutbox();
  if (!$time) $time = mq($_REQUEST['time']);
  $items = $outbox[$time];
  $timestr = hsc($time);
  if ($items) {
    foreach ($items as $item) {
      $request = $item[$t->REQUEST];
      if ($request == $t->SPEND) {
        $assetname = hsc($item[$t->ASSETNAME]);
        $formattedamount = hsc($item[$t->FORMATTEDAMOUNT]);
        $note = hsc($item[$t->NOTE]);
        if ($note) $note = "<b>Note:</b> $note<br/>\n";
      } elseif ($request == $t->COUPONENVELOPE) {
        $coupon = hsc(trim($item[$t->COUPON]));
        $body = <<<EOT
<br/>
<b>Coupon for outbox entry $timestr</b>
<br/>
<b>Amount:</b> $formattedamount $assetname
<br/>
$note<br/>
<textarea style="padding: 5px;" name="coupon" cols="90" rows="12" readonly="readonly">
$coupon
</textarea>
<p>
You can redeem this coupon on the
<a href="./?cmd=banks">Banks</a> screen. It will appear as a spend from yourself.
</p>
EOT;
        return;
      }
    }
  }
  echo "Couldn't find coupon: $timestr<br/>\n";
  draw_balance();
}

function draw_raw_balance() {
  global $body;
  global $client;

  settitle('Raw Balance');
  setmenu('balance');

  if ($client) {
    $t = $client->t;
    $db = $client->db;
    $id = $client->id;
    $bankid = $client->bankid;
    if (!($id && $bankid)) return;

    $body = '';


    $key = $client->userbankkey($t->INBOX);
    $inbox = $db->contents($key);
    if (count($inbox) == 0) {
      $body .= "<br/><b>=== Inbox empty ===</b><br/>\n";
    } else {
      $body .= '<br/><b>=== Inbox ===</b><br/>
<table border="1">

';
      foreach ($inbox as $file) {
        $msg = $db->get("$key/$file");
        $body .= <<<EOT
<tr>
<td valign="top">$file</td>
<td><pre>$msg</pre></td>
</tr>

EOT;
      }
      $body .= "</table>\n";
    }

    $key = $client->userbankkey($t->OUTBOX);
    $outbox = $db->contents($key);
    if (count($outbox) == 0) {
      $body .= "<br/><b>=== Outbox empty ===</b><br/>\n";
    } else {
      $body .= '<br/><b>=== Outbox===</b><br/>
<table border="1">

';
      foreach ($outbox as $file) {
        $msg = $db->get("$key/$file");
        $body .= <<<EOT
<tr>
<td valign="top">$file</td>
<td><pre>$msg</pre></td>
</tr>

EOT;
      }
      $body .= "</table>\n";
    }

    $key = $client->userbankkey($t->BALANCE);
    $accts = $db->contents($key);
    foreach ($accts as $acct) {
      $body .= '<br/><b>' . $acct . '</b><br/>
<table border="1">

';
      $assets = $db->contents("$key/$acct");
      foreach ($assets as $assetid) {
        $asset = $client->getasset($assetid);
        $assetname = $asset[$t->ASSETNAME];
        $msg = $db->get("$key/$acct/$assetid");
        $body .= <<<EOT
<tr>
<td valign="top">$assetname</td>
<td><pre>$msg</pre></td>
</tr>
EOT;
      }
      $body .= "</table><br/>\n";
    }
  }
}

function draw_banks($bankurl='', $name='') {
  global $onload, $body;
  global $error;
  global $client;

  $t = $client->t;

  $banks = $client->getbanks();

  $onload = "document.forms[0].bankurl.focus()";
  settitle('Banks');
  setmenu('banks');

  $body .= <<<EOT
<span style="color: red;">$error</span><br/>
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="bank"/>
<table>
<tr>
<td><b>Bank URL<br/>or Coupon:</b></td>
<td><textarea name="bankurl" cols="40" rows="2">$bankurl</textarea>
</tr><tr>
<td><b>Account Name<br/>(optional):</b></td>
<td><input type="text" name="name" size="40" value="$name"/></td>
</tr><tr>
<td></td>
<td><input type="submit" name="newbank" value="Add Bank"/>
<input type="submit" name="cancel" value="Cancel"/></td>
</tr>
</table>
</form>

EOT;

  if (count($banks) > 0) {
    $body .= '<table border="1">
<tr>
<th>Bank</th>
<th>URL</th>
<th>ID</th>
<th>Choose</th>
</tr>
';
    foreach ($banks as $bid => $b) {
      if ($client->userreq($bid) != -1) {
        $name = hsc($b[$t->NAME]);
        if (!$name) $name = "unnamed";
        $url = hsc($b[$t->URL]);
        $body .= <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="bank"/>
<input type="hidden" name="bank" value="$bid"/>
<tr>
<td>$name</td>
<td><a href="$url">$url</a></td>
<td>$bid</td>
<td><input type="submit" name="selectbank" value="Choose"/></td>
</tr>
</form>

EOT;
      }
    }
    $body .= "</table>\n";
  }
  
}

function draw_contacts($id=false, $nickname=false, $notes=false) {
  global $onload, $body;
  global $error;
  global $client;

  $t = $client->t;

  $onload = "document.forms[0].id.focus()";
  settitle('Contacts');
  setmenu('contacts');

  $id = hsc($id);
  $nickname = hsc($nickname);
  $notes = hsc($notes);

  $body = <<<EOT
<span style="color: red;">$error</span><br/>
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="contact">
<table>
<tr>
<td align="right"><b>ID:</b></td>
<td><input type="text" name="id" size="40" value="$id"/></td>
</tr><tr>
<td><b>Nickname<br/>(Optional):</b></td>
<td><input type="text" name="nickname" size="30" value="$nickname"/></td>
</tr><tr>
<td><b>Notes<br/>(Optional):</b></td>
<td><textarea name="notes" cols="30" rows="10">$notes</textarea></td>
</tr><tr>
<td></td>
<td><input type="submit" name="addcontact" value="Add/Change Contact"/>
<input type="submit" name="cancel" value="Cancel"/></td>
</tr>
</table>

EOT;

  $contacts = $client->getcontacts();
  $cnt = count($contacts);
  if ($cnt > 0) {
    $body .= '<br/><form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="contact"/>
<input type="hidden" name="chkcnt" value="' . $cnt . '"/>
<table border="1">
<tr>
<th>Nickname</th>
<th>Name</th>
<th>Display</th>
<th>ID</th>
<th>Notes</th>
<th>x</th>
</tr>';
    $idx = 0;
    foreach ($contacts as $contact) {
      $id = hsc($contact[$t->ID]);
      $name = trim(hsc($contact[$t->NAME]));
      $nickname = trim(hsc($contact[$t->NICKNAME]));
      $display = namestr($nickname, $name, $id);
      if (!$name) $name = '&nbsp;';
      if (!$nickname) $nickname = '&nbsp;';
      
      $note = hsc($contact[$t->NOTE]);
      if (!$note) $note = "&nbsp;";
      else $note = str_replace("\n", "<br/>\n", $note);
      $body .= <<<EOT
<tr>
<td>$nickname</td>
<td>$name</td>
<td>$display</td>
<td>$id</td>
<td>$note</td>
<td>
<input type="hidden" name="id$idx" value="$id"/>
<input type="checkbox" name="chk$idx"/>
</td>
</tr>

EOT;
      $idx++;
    }
    $body .= <<<EOT
</table>
<br/>
<input type="submit" name="deletecontacts" value="Delete checked"/>
</form>
EOT;
  }
}

function draw_assets($scale=false, $precision=false, $assetname=false) {
  global $onload, $body;
  global $error;
  global $client;

  $t = $client->t;

  $onload = "document.forms[0].scale.focus()";

  settitle('Assets');
  setmenu('assets');

  $scale = hsc($scale);
  $precision = hsc($precision);
  $assetname = hsc($assetname);

  $body .= <<<EOT
<span style="color: red;">$error</span><br/>
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="asset"/>
<table>
<tr>
<td><b>Scale:</b></td>
<td><input type="text" name="scale" size="3" value="$scale"/>
</tr><tr>
<td><b>Precision:</b></td>
<td><input type="text" name="precision" size="3" value="$precision"/></td>
</tr><tr>
<td><b>Asset name:</b></td>
<td><input type="text" name="assetname" size="30" value="$assetname"/></td>
</tr><tr>
<td></td>
<td><input type="submit" name="newasset" value="Add Asset"/>
<input type="submit" name="cancel" value="Cancel"/></td>
</tr>
</table>
</form>

EOT;

  $assets = $client->getassets();
  if (count($assets) > 0) {
    $body .= '<table border="1">
<tr>
<th>Asset name</th>
<th>Scale</th>
<th>Precision</th>
<th>Owner</th>
<th>Asset ID</th>
</tr>
';
    foreach ($assets as $asset) {
      $ownerid = $asset[$t->ID];
      $contact = $client->getcontact($ownerid);
      if ($contact) {
        $namestr = contact_namestr($contact);
        if ($namestr != $ownerid) {
          $namestr = "<span title=\"$ownerid\">$namestr<span>";
        }
      } else $namestr = hsc($ownerid);
      $assetid = $asset[$t->ASSET];
      $scale = $asset[$t->SCALE];
      $precision = $asset[$t->PRECISION];
      $assetname = $asset[$t->ASSETNAME];
      $body .= <<<EOT
<tr>
<td>$assetname</td>
<td align="right">$scale</td>
<td align="right">$precision</td>
<td>$namestr</td>
<td>$assetid</td>
</tr>

EOT;
    }
    $body .= "</table>\n";
  }
}

function draw_admin($name=false, $tokens=false) {
  global $onload, $body;
  global $error;
  global $client;

  settitle('Admin');
  setmenu('admin');

  $onload = "document.forms[0].name.focus()";

  $body = 'No admin stuff yet';
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
