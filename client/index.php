<?php

  // client/index.php
  // A Trubanc web client

// Define $dbdir, $default_server
require_once "settings.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

$cmd = mq($_POST['cmd']);

if (!$cmd) draw_login();
elseif ($cmd == 'login') do_login();
else {

  require_once "../lib/fsdb.php";
  require_once "../lib/ssl.php";
  require_once "../lib/client.php";

  $db = new fsdb($dbdir);
  $ssl = new ssl();
  $client = new client($db, $ssl);

  if ($cmd == 'balance') draw_balance();
}

function draw_login() {
  global $title, $body, $onload;

  $title = "Trubanc Web Client";
  $onload = "document.forms[0].passphrase.focus()";
  $body = <<<EOT
<form method="post" action="" autocomplete="off">
<input type="hidden" name="cmd" value="login"/>
<table>
<tr>
<td>Passphrase:</td>
<td><input type="text" name="passphrase" size="50"/>
<input type="submit" name="login" value="Login"/></td>
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
and a key size (512, 1024, 2048, 3072, or 4096), and click "Create account".</td>
</tr>
</table></td>
</tr><tr>
<td></td>
<td><textarea name="privkey" cols="64" rows="40"></textarea></td>
</table>
EOT;
  include "template.php";
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
