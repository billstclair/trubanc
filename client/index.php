<?php

  // client/index.php
  // A Trubanc web client

// Define $dbdir, $default_server
require_once "settings.php";

require_once "../lib/fsdb.php";
require_once "../lib/ssl.php";
require_once "../lib/client.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

$cmd = mq($_REQUEST['cmd']);

$db = new fsdb($dbdir);
$ssl = new ssl();
$client = new client($db, $ssl);

$accts = $db->contents('account');

$title = "Trubanc Web Client";
$menu = '<a href="./?cmd=logout">Logout</a>';

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

if (!$cmd) draw_login();
elseif ($cmd == 'logout') do_logout();
elseif ($cmd == 'login') do_login();
elseif ($cmd == 'bank') do_bank();
elseif ($cmd == 'balance') draw_balance();
elseif ($cmd == 'addbank') draw_addbank();

// Use $title, $body, and $onload to fill the page template.
include "template.php";

function do_logout() {
  global $session, $client, $menu;

  if ($session) $client->logout();
  setcookie('session', false);
  draw_login();
}

// Here from the login page when the user presses one of the buttons
function do_login() {
  global $title, $body, $onload;
  global $keysize;
  global $error;
  global $client, $ssl;

  $passphrase = mq($_POST['passphrase']);
  $passphrase2 = mq($_POST['passphrase2']);
  $keysize = mq($_POST['keysize']);
  $login = mq($_POST['login']);
  $newacct = mq($_POST['newacct']);

  if ($newacct) {
    $login = false;
    if ($passphrase != $passphrase2) {
      $error = "Passphrase didn't match Verification";
      draw_login();
    } else {
      $privkey = mq($_POST['privkey']);
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
        $login = true;
      }
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
  }
  draw_balance();
}

function draw_login() {
  global $title, $menu, $body, $onload;
  global $keysize;
  global $error;

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
<td>Passphrase:</td>
<td><input type="password" name="passphrase" size="50"/>
<input type="submit" name="login" value="Login"/></td>
</tr><tr>
<td></td>
<td style="color: red">$error&nbsp;</td>
</tr><tr>
<td>Verification:</td>
<td><input type="password" name="passphrase2" size="50"/>
</tr><tr>
<td>Key size:</td>
<td>
<select name="keysize">
<option value="512"$sel512>512</option>
<option value="1024"$sel1024>1024</option>
<option value="2048"$sel2048>2048</option>
<option value="3072"$sel3072>3072</option>
<option value="4096"$sel4096>4096</option>
</select>
<input type="submit" name="newacct" value="Create account"/></td>
</tr><tr>
<td></td>
<td><table>
<tr><td style="width: 32em;">
To generate a new private key, leave the area below blank, enter a
passphrase, the passphrase again to verify, a key size, and click the
"Create account" button.  To use an existing private key, paste the
private key below, enter its passphrase and verification above, and
click the "Create account" button.
</td>
</tr>
</table></td>
</tr><tr>
<td></td>
<td><textarea name="privkey" cols="64" rows="40"></textarea></td>
</table>

EOT;
}

function idcode() {
  global $client;

  $id = $client->id;
  return "<b>Your ID:</b> $id<br/><br/>\n";
}

function draw_balance() {
  global $client;
  global $error;
  global $body;
  
  $t = $client->t;

  $saveerror = $error;
  $error = false;

  $banks = $client->getbanks();
  $bank = false;
  $bankid = $client->userpreference('bankid');
  if ($bankid) {
    $err = $client->setbank($bankid);
    if ($err) $bankid = false;
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

  $idcode = idcode();

  $bankcode = "<form method=\"post\" action=\"./\">
<input type=\"hidden\" name=\"cmd\" value=\"bank\">\n";

  if ($bank) {
    $name = $bank[$t->NAME];
    $url = $bank[$t->URL];
    $bankcode .= "<b>Bank:</b> $name <a href=\"$url\">$url</a>";
  }
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
  $addbankcode = '<a href="./?cmd=addbank">Add bank</a><br/>';
  if ($bankopts) {
    $bankcode .= <<<EOT
<br>
<select name="bank">
<option value="">Choose a bank...</option>
$bankopts
</select>
<input type="submit" name="selectbank" value="Change Bank"/>
$addbankcode

EOT;
  } else {
    $bankcode .= " $addbankcode\n";
  }
  $bankcode .= "</form>\n";

  $balcode = '';
  if (!$error) {
    $balance = $client->getbalance();
    if (is_string($balance)) $error = $balance;
    else {
      $balcode = "<table>\n";
      foreach ($balance as $acct => $assets) {
        $balcode .= "<tr><td></td><td><b>$acct</b></td></tr>\n";
        foreach ($assets as $asset => $data) {
          $assetname = $data[$t->ASSETNAME];
          $formattedamount = $data[$t->FORMATTEDAMOUNT];
          $balcode .= <<<EOT
<tr>
<td align="right"><span style="margin-right: 5px">$formattedamount</span></td>
<td>$assetname</td>
</tr>

EOT;
        }
      }
      $balcode .= "</table>\n";
    }
  }

  if ($saveerror) {
    if ($error) $error = "$saveerror<br/>$error";
    else $error = $saveerror;
  }
  if ($error) {
    $error = "<span style=\"color: red\";\">$error</span>\n";
  }
  $body = "$error<br/>$idcode$bankcode$balcode";
}

function draw_addbank() {
  global $body;

  $idcode = idcode();
  $body .= <<<EOT
$idcode
<form method="post" action="./">
<input type="hidden" name="cmd" value="bank"/>
<table>
<tr>
<td>Bank URL:</td>
<td><input type="text" name="bankurl" size="40"/>
</tr><tr>
<td>Name (optional):</td>
<td><input type="text" name="name" size="40"/></td>
</tr><tr>
<td></td>
<td><input type="submit" name="newbank" value="Add Bank"/>
<input type="submit" name="cancel" value="Cancel"/></td>
</tr>
</table>
</form>

EOT;

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
