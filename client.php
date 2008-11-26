<?php

  // client.php
  // A Trubanc web client

// Define $dbdir, $default_server
require_once "client-settings.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

$cmd = mq($_POST['cmd']);

if (!$cmd) draw_login();
elseif ($cmd == 'login') do_login();
else {

  require_once "lib/fsdb.php";
  require_once "lib/ssl.php";
  require_once "lib/client.php";

  $db = new fsdb($dbdir);
  $ssl = new ssl();
  $client = new client($db, $ssl);

  if ($cmd == 'balance') draw_balance();
}

function draw_login() {
  global $client;
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
