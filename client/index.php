<?php

  // client/index.php
  // A Trubanc web client

// Define $dbdir, $default_server, $require_tokens
require_once "settings.php";

require_once "../lib/fsdb.php";
require_once "../lib/ssl.php";
require_once "../lib/client.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

function hsc($x) {
  return htmlspecialchars($x);
}

$cmd = mq($_REQUEST['cmd']);

$db = new fsdb($dbdir);
$ssl = new ssl();
$client = new client($db, $ssl);

$default_menuitems = array('balance' => 'Balance',
                           'contacts' => 'Contacts',
                           'banks' => 'Banks',
                           'admins' => 'Admin',
                           'logout' => 'Logout');

// Initialize (global) inputs to template.php
$title = "Trubanc Web Client";
$bankline = '';

$error = false;

$session = $_COOKIE['session'];
if ($session) {
  $err = $client->login_with_sessionid($session);
  if ($err) {
    $error = "Session login error: $err";
    $cmd = 'logout';
    $session = false;
  } else {
    if (!$cmd) $cmd = 'balance';
  }
}

if ($client->id) setbank();

if (!$client->bankid) {
  if ($cmd && $cmd != 'logout' && $cmd != 'login') {
    $cmd = 'balance';
  }
}

if (!$cmd) draw_login();
elseif ($cmd == 'logout') do_logout();
elseif ($cmd == 'login') do_login();
elseif ($cmd == 'bank') do_bank();
elseif ($cmd == 'contact') do_contact();
elseif ($cmd == 'admin') do_admin();
elseif ($cmd == 'spend') do_spend();
elseif ($cmd == 'balance') draw_balance();
elseif ($cmd == 'contacts') draw_contacts();
elseif ($cmd == 'banks') draw_banks();
elseif ($cmd == 'admins') draw_admin();
elseif ($session) draw_balance();
else draw_login();

// Use $title, $body, and $onload to fill the page template.
include "template.php";

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
  global $keysize, $require_tokens;
  global $error;
  global $client, $ssl;

  $passphrase = mq($_POST['passphrase']);
  $passphrase2 = mq($_POST['passphrase2']);
  $keysize = mq($_POST['keysize']);
  $login = mq($_POST['login']);
  $newacct = mq($_POST['newacct']);
  $showkey = mq($_POST['showkey']);

  if ($showkey) {
    $key = $client->getprivkey($passphrase);
    if (!$key) $error = "No key for passphrase";
    draw_login($key);
  }
  if ($newacct) {
    $login = false;
    $privkey = mq($_POST['privkey']);
    if (!$privkey && $passphrase != $passphrase2) {
      $error = "Passphrase didn't match Verification";
      draw_login();
    } else {
      if ($require_tokens) {
        $tok = mq($_POST['tok']);
        $token = $client->token($tok);
        if (!$token) {
          $error = "You must get an invitation token from the owner of this web site";
          draw_login();
          return;
        }
      }
      if ($privkey) {
        // Support adding a passphrase to a private key without one
        $pk = $ssl->load_private_key($privkey);
        if ($pk) {
          openssl_pkey_export($pk, $privkey, $passphrase);
          openssl_free_key($pk);
        }
      } else $privkey = $keysize;
      $err = $client->newuser($passphrase, $privkey);
      if ($err) {
        $error = $err;
        draw_login();
      } else {
        if ($require_tokens) {
          // It would be nice to give the user some usage tokens here
          // and register him with the bank, but I need bearer
          // certificates in the server to do that.
          // The bank is a client, but we don't know its passphrase,
          // and we don't want to.
          // So just remove the token
          $client->token($tok, '');
        }
      }
      $login = true;
    }
  }

  if ($login) {
    $session = $client->login_new_session($passphrase);
    if (is_string($session)) {
      $error = "Login error: $session";
      draw_login();
    } else {
      $session = $session[0];
      if (!setcookie('session', $session)) {
        $error = "You must enable cookies to use this client";
        draw_login();
      } else {
        setbank();
        draw_balance();
      }
    }
  }
}

// Here to change banks or add a new bank
function do_bank() {
  global $client;
  global $error;

  $newbank = mq($_POST['newbank']);
  $selectbank = mq($_POST['selectbank']);

  if ($newbank) {
    $bankurl = mq($_POST['bankurl']);
    $name = mq($_POST['name']);
    $error = $client->addbank($bankurl);
    if (!$error) {
      if ($client->userreq() == -1) {
        $error = $client->register($name);
      }
      if (!$error) $client->userpreference('bankid', $client->bankid);
    }
  } elseif ($selectbank) {
    $bankid = mq($_POST['bank']);
    if (!$bankid) $error = "You must choose a bank";
    else $client->userpreference('bankid', $bankid);
    setbank(true);
  }
  if ($error) draw_banks();
  else draw_balance();
}

function do_contact() {
  global $client;
  global $error;

  $addcontact = $_POST['addcontact'];

  if ($addcontact) {
    $id = $_POST['id'];
    $nickname = $_POST['nickname'];
    $notes = $_POST['notes'];
    $err = $client->addcontact($id, $nickname, $notes);
    if ($err) {
      $error = "Can't add contact: $err";
      draw_contacts($id, $nickname, $notes);
    } else draw_contacts();
  } else draw_balance();
}

function do_admin() {
  global $client;

  $createtoken = $_POST['createtoken'];
  $removetoken = $_POST['removetoken'];
  $cancel = $_POST['cancel'];

  if ($createtoken) {
    $name = mq($_POST['name']);
    $count = mq($_POST['count']);
    $tokens = mq($_POST['tokens']);
    $res = '';
    for ($i=0; $i<$count; $i++) {
      $tok = $client->newsessionid();
      $client->token($tok, "$tokens|$name");
      if ($res) $res .= ' ';
      $res .= $tok;
    }
    draw_admin($name, $res);
  } elseif ($removetoken) {
    $tok = mq($_POST['tok']);
    $client->token($tok, '');
    draw_admin();
  } elseif ($cancel) {
    draw_balance();
  } else draw_admin();
}

function do_spend() {
  global $error;
  global $client;

  $amount = mq($_POST['amount']);
  $recipient = mq($_POST['recipient']);
  $note = mq($_POST['note']);
  if (!$amount || !$recipient) {
    $error = "Spend amount or Recipient missing";
    draw_balance($amount, $recipient, $note);
  } else {
    $found = false;
    foreach ($_POST as $key => $value) {
      $prefix = 'spentasset';
      $prelen = strlen($prefix);
      if (substr($key, 0, $prelen) == $prefix) {
        $acctdotasset = substr($key, $prelen);
        $acctdotasset = explode('|', $acctdotasset);
        if (count($acctdotasset) != 2) {
          $error = "Bug: don't understand spentasset";
          draw_balance($amount, $recipient, $note);
        } else {
          $acctidx = $acctdotasset[0];
          $assetidx = $acctdotasset[1];
          $acct = mq($_POST["acct$acctidx"]);
          $assetid = mq($_POST["assetid$acctidx|$assetidx"]);
          if (!$acct || !$assetid) {
            $error = "Bug: blank acct or assetid";
            draw_balance($amount, $recipient, $note);
          } else {
            $err = $client->spend($recipient, $assetid, $amount, $acct, $note);
            if ($err) {
              $error = "Error from spend: $err";
              draw_balance($amount, $recipient, $note);
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
      draw_balance($amount, $recipient, $note);
    }
  }
}

function draw_login($key=false) {
  global $title, $menu, $body, $onload;
  global $keysize, $require_tokens;
  global $error;

  $key = hsc($key);

  if (!$keysize) $keysize = 3072;
  $sel = ' selected="selected"';
  $sel512 = ($keysize == 512) ? $sel : '';
  $sel1024 = ($keysize == 1024) ? $sel : '';
  $sel2048 = ($keysize == 2048) ? $sel : '';
  $sel3072 = ($keysize == 3072) ? $sel : '';
  $sel4096 = ($keysize == 4096) ? $sel : '';

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
</tr><tr>
<td><b>Verification:</b></td>
<td><input type="password" name="passphrase2" size="50"/>
</tr><tr>

EOT;

  if ($require_tokens) {
    $body .= <<<EOT
<td><b>Invitation<br/>token:</b></td>
<td><input type="text" name="tok" size="40"/></td>
</tr><tr>
EOT;
  }

  $body .= <<<EOT
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
passphrase, the passphrase again to verify, a key size, and click the
"Create account" button.  To use an existing private key, paste the
private key below, enter its passphrase above, and click the
"Create account" button. To show your encrypted private key, enter
its passphrase, and click the "Show key" button.
</td>
</tr><tr>
<td></td>
<td><textarea name="privkey" cols="64" rows="42">$key</textarea></td>
</table>

EOT;
}

function idcode() {
  global $client;

  $id = '';
  if ($client) $id = $client->id;
  return $id ? "<b>Your ID:</b> $id<br/>\n": '';
}

function setbank($reporterror=false) {
  global $banks, $bank, $bankline;
  global $error;
  global $client;

  $t = $client->t;

  $banks = $client->getbanks();
  $bank = false;
  $bankid = $client->userpreference('bankid');
  if ($bankid) {
    $err = $client->setbank($bankid, false);
    if ($err) {
      if ($reporterror) $error = "Can't set bank: $err";
      $bankid = false;
    }
  }
  if (!$bankid) {
    foreach ($banks as $bank) break;
    if ($bank) {
      $bankid = $bank[$t->BANKID];
      $err = $client->setbank($bankid);
      if ($err) {
        $error = "Can't set bank: $err";
        $bankid = false;
      } else {
        $client->userpreference('bankid', $bankid);
      }
    } else {
      $error = "No known banks. Please add one.";
    }
  }
  $bank = $banks[$bankid];

  if ($bank) {
    $name = $bank[$t->NAME];
    $url = $bank[$t->URL];
    $bankline = "<b>Bank:</b> $name <a href=\"$url\">$url</a><br/>\n";
  }
}

function draw_balance($spend_amount=false, $recipient=false, $note=false) {
  global $client, $banks, $bank;
  global $error;
  global $onload, $body;
  
  $t = $client->t;

  setmenu('balance');

  $saveerror = $error;
  $error = false;

  $bankid = '';
  if ($bank) $bankid = $bank[$t->BANKID];

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
<form method="post" action="./">
<input type="hidden" name="cmd" value="bank">
<select name="bank">
<option value="">Choose a bank...</option>
$bankopts
</select>
<input type="submit" name="selectbank" value="Change Bank"/>
</form>

EOT;
  }

  $balcode = '';
  $assetlist = '';
  $assetidx = 0;
  $acctidx = 0;
  $gotbal = false;
  $contacts = $client->getcontacts();
  $havecontacts = (count($contacts) > 0);

  if (!$error && $client->bankid) {
    $balance = $client->getbalance();
    if (is_string($balance)) $error = $balance;
    else {
      $balcode = "<table>\n";
      foreach ($balance as $acct => $assets) {
        $acct = hsc($acct);
        $balcode .= "<tr><td></td><td><b>$acct</b></td></tr>\n";
        $newassetlist = '';
        foreach ($assets as $asset => $data) {
          if ($data[$t->AMOUNT] != 0) {
            $gotbal = true;
            $assetid = hsc($data[$t->ASSET]);
            $assetname = hsc($data[$t->ASSETNAME]);
            $formattedamount = hsc($data[$t->FORMATTEDAMOUNT]);
            $submitcode = '';
            if ($havecontacts) {
              $newassetlist .= <<<EOT
<input type="hidden" name="assetid$acctidx|$assetidx" value="$assetid"/>

EOT;
              $submitcode = <<<EOT
<input type="submit" name="spentasset$acctidx|$assetidx" value="Spend"/>

EOT;
              $assetidx++;
            }
            $balcode .= <<<EOT
<tr>
<td align="right"><span style="margin-right: 5px">$formattedamount</span></td>
<td>$assetname</td>
<td>$submitcode</td>
</tr>

EOT;
          }
        }
        if ($newassetlist) {
          $assetlist .= <<<EOT
<input type="hidden" name="acct$acctidx" value="$acct"/>
$newassetlist
EOT;
          $acctidx++;
        }
      }
      $balcode .= "</table>\n";
    }
  }

  $spendcode = '';
  $closespend = '';
  if ($gotbal && $havecontacts) {
    $recipopts = '<select name="recipient">
<option value="">Choose recipient...</option>
';
    foreach ($contacts as $contact) {
      $name = hsc($contact[$t->NAME]);
      $nickname = hsc($contact[$t->NICKNAME]);
      $recipid = hsc($contact[$t->ID]);
      if ($nickname) {
        if ($name && $name != $nickname) $namestr = "$nickname ($name)";
      } elseif ($name) $namestr = $name;
      else $namestr = "id: recipid";
      $selected = '';
      if ($recipid == $recipient) $selected = ' selected="selected"';
      $recipopts .= <<<EOT
<option value="$recipid"$selected>$namestr</option>

EOT;
    }
    $recipopts .= "</select>\n";
    $spendcode = <<<EOT

To make a spend, fill in the "Spend amount", "Recipient", and (optionally) "Note",
and click the "Spend" button next to the asset you wish to spend.<br/><br/>

<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="spend"/>
<table>
<tr>
<td><b>Spend amount:</b></td>
<td><input type="text" name="amount" size="20" value="$spend_amount" style="text-align: right;"/>
</tr><tr>
<td><b>Recipient:</b></td>
<td>$recipopts</td>
</tr><tr>
<td><b>Note:</b></td>
<td><textarea name="note" cols="30" rows="10">$note</textarea></td>
</tr>
</table>
<br/>

EOT;
    $onload = "document.forms[0].amount.focus()";
    $closespend = "</form>\n";
  }

  if ($saveerror) {
    if ($error) $error = "$saveerror<br/>$error";
    else $error = $saveerror;
  }
  if ($error) {
    $error = "<span style=\"color: red\";\">$error</span>\n";
  }
  $body = "$error<br>$bankcode$spendcode$assetlist$balcode$closespend";
}

function draw_banks() {
  global $onload, $body;
  global $error;
  global $client, $banks, $bank;

  $t = $client->t;

  $onload = "document.forms[0].bankurl.focus()";

  setmenu('banks');

  $body .= <<<EOT
<span style="color: red;">$error</span><br>
<form method="post" action="./">
<input type="hidden" name="cmd" value="bank"/>
<table>
<tr>
<td><b>Bank URL:</b></td>
<td><input type="text" name="bankurl" size="40"/>
</tr><tr>
<td><b>Account Name<br>(optional):</b></td>
<td><input type="text" name="name" size="40"/></td>
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
<form method="post" action="./">
<input type="hidden" name="cmd" value="bank"/>
<input type="hidden" name="bank" value="$bid"/>
<tr>
<td>$name</td>
<td><a href="$url">$url</a></td>
<td>$bid</td>
<td><input type="submit" name="selectbank" value="Choose"/></td>
</tr>
</form>
</table>

EOT;
      }
    }
  }
  
}

function draw_contacts($id=false, $nickname=false, $notes=false) {
  global $onload, $body;
  global $error;
  global $client;

  $t = $client->t;

  $onload = "document.forms[0].id.focus()";
  setmenu('contacts');

  $id = hsc($id);
  $nickname = hsc($nickname);
  $notes = hsc($notes);

  $body = <<<EOT
<span style="color: red;">$error</span><br/>
<form method="post" action="./">
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
  if (count($contacts) > 0) {
    $body .= '<br/><table border="1">
<tr>
<th>Name</th>
<th>Nickname</th>
<th>ID</th>
<th>Notes</th>
</tr>';
    foreach ($contacts as $contact) {
      $id = hsc($contact[$t->ID]);
      $name = hsc($contact[$t->NAME]);
      $nickname = hsc($contact[$t->NICKNAME]);
      $note = hsc($contact[$t->NOTE]);
      $note = str_replace("\n", "<br/>\n", $note);
      $body .= <<<EOT
<tr>
<td>$name</td>
<td>$nickname</td>
<td>$id</td>
<td>$note</td>
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

  setmenu('admin');

  $onload = "document.forms[0].name.focus()";

  $name = hsc($name);
  $tokens = hsc($tokens);

  $body = <<<EOT
<br/>
<form method="post" action="./">
<input type="hidden" name="cmd" value="admin"/>
<table>
<tr>
<td align="right"><b>Name:</b></td>
<td><input type="text" name="name" width="30" value="$name"/></td>
</tr><tr>
<td align="right"><b>Count:</b></td>
<td><input type="text" name="count" value="1"/>
</tr><tr>
<td><b>Usage tokens:</b></td>
<td><input type="text" name="tokens" value="50"/>
</tr><tr>
<td></td>
<td><input type="submit" name="createtoken" value="Create account token(s)"/>
<input type="submit" name="cancel" value="Cancel"/></td>
</tr>
</table>

EOT;
  if ($tokens) {
    $body .= <<<EOT
<br/>
<table>
<tr>
<th>Tokens:</th>
<td><textarea readonly="readonly" id="tokens" rows="10" cols="40">$tokens</textarea></td>
</tr>
</table>
</span>

EOT;
  } else {
    $tokens = $client->gettokens();
    if (count($tokens) > 0) {
      $body .= '<table border="1">
<tr>
<th>Name</th>
<th>Usage Tokens</th>
<th>Token</th>
<th>Remove</th>
</tr>';
      foreach ($tokens as $tok => $token) {
        $tok = hsc($tok);
        $token = explode('|', $token);
        $tokcnt = hsc($token[0]);
        $name = hsc($token[1]);
        $body .= <<<EOT
<form method="post" action="./">
<input type="hidden" name="cmd" value="admin"/>
<input type="hidden" name="tok" value="$tok"/>
<tr>
<td>$name</td>
<td align="right">$tokcnt</td>
<td>$tok</td>
<td><input type="submit" name="removetoken" value="Remove"/></td>
</tr>
</form>

EOT;
      }
      $body .= "</table>\n";
    }
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
