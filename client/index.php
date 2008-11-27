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

$session = $_COOKIE['session'];
if ($session) {
  $err = $client->login_with_sessionid($session);
  if ($err) {
    $error = "Session login error: $err";
    $cmd = 'logout';
    $session = false;
  } elseif (!$cmd) $cmd = 'balance';
}

if (!$cmd) draw_login();
elseif ($cmd == 'logout') {
  if ($session) $client->logout();
  setcookie('session', false);
  draw_login();
}
else {
  if ($cmd == 'login') do_login();
  elseif ($cmd == 'balance') draw_balance();
}

// Use $title, $body, and $onload to fill the page template.
include "template.php";

function do_login() {
  global $title, $body, $onload;
  global $error;
  global $client;

  $passphrase = mq($_REQUEST['passphrase']);
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

function draw_login() {
  global $title, $body, $onload;
  global $error;

  $onload = "document.forms[0].passphrase.focus()";
  $body = <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="login"/>
<table>
<tr>
<td>Passphrase:</td>
<td><input type="text" name="passphrase" size="50"/>
<input type="submit" name="login" value="Login"/></td>
</tr><tr>
<td></td>
<td style="color: red">$error&nbsp;</td>
</tr><tr>
<td>Key size:</td>
<td><input type="text" name="keysize" size="4" value="3072"/>
<input type="submit" name="newaccount" value="Create account"/></td>
</tr><tr>
<td></td>
<td><table>
<tr><td style="width: 32em;">To use an existing private key, paste the encrypted private
key below, enter its passphrase above, and click the "Create account" button.
To generate a new private key, leave the area below blank, enter a passphrase
and a key size (512, 1024, 2048, 3072, or 4096), and click the "Create account"
button.</td>
</tr>
</table></td>
</tr><tr>
<td></td>
<td><textarea name="privkey" cols="64" rows="40"></textarea></td>
</table>
EOT;
}

function draw_balance() {
  global $client;
  global $body;
  
  $t = $client->t;

  $banks = $client->getbanks();
  $bank = false;
  $error = false;
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

  $bankcode = '';
  if ($bank) {
    $name = $bank[$t->NAME];
    $url = $bank[$t->URL];
    $bankcode = "<b>Bank:</b> $name $url<br>\n";
  }

  $balcode = '';
  if (!$error) {
    $balance = $client->getbalance();
    if (is_string($balance)) $error = $balance;
    else {
      $balcode = "<table>\n";
      foreach ($balance as $acct => $assets) {
        $balcode .= "<tr><td colspan=\"3\"><b>$acct</b></td></tr>\n";
        foreach ($assets as $asset => $data) {
          $assetname = $data[$t->ASSETNAME];
          $formattedamount = $data[$t->FORMATTEDAMOUNT];
          $balcode .= <<<EOT
<tr>
<td>&nbsp;&nbsp;</td>
<td>$formattedamount </td>
<td>$assetname</td>
</tr>
EOT;
                    
        }
      }
      $balcode .= "</table>\n";
    }
  }

  $body = "$error<br/>$bankcode$balcode";
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
