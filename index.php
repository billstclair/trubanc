<?php

  // index.php
  // Trubanc main page

// Define $dbdir, $bank_name, $index_file, $bankurl
require_once "settings.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

function mqreq($x) {
  return mq($_REQUEST[$x]);
}

$msg = mqreq('msg');
$debug = mqreq('debug');
$debugdir = mqreq('debugdir');
$debugfile = mqreq('debugfile');

if ($msg) {

  require_once "lib/fsdb.php";
  require_once "lib/ssl.php";
  require_once "lib/server.php";

  $db = new fsdb($dbdir);
  $ssl = new ssl();
  $server = new server($db, $ssl, false, $bank_name, $bankurl);
  if ($debugdir && $debugfile) $server->setdebugdir($debugdir, $debugfile);
  if ($debug) {
    echo "msg: <pre>$msg</pre>\n";
    echo "response: <pre>";
  }
  echo $server->process($msg);
  if ($debug) {
    echo "</pre>\n";
  }

} else {
  echo file_get_contents($index_file);
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
