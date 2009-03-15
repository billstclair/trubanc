<?php

  // index.php
  // Trubanc main page

require_once "lib/weblib.php";

// Define $dbdir, $bank_name, $index_file, $bankurl, $ssl_domain
if (file_exists("settings.php")) require_once "settings.php";

die_unless_server_properly_configured();
maybe_forward_to_ssl($ssl_domain);

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

function mqreq($x) {
  return mq($_REQUEST[$x]);
}

$msg = mqreq('msg');
$debug = mqreq('debug');
$debugmsgs = mqreq('debugmsgs');

if ($msg) {

  require_once "lib/fsdb.php";
  require_once "lib/ssl.php";
  require_once "lib/server.php";
  require_once "lib/perf.php";

  $db = new fsdb($dbdir);
  $ssl = new ssl();
  $server = new server($db, $ssl, false, $bank_name, $bankurl);
  if ($debugmsgs) {
    $server->setdebugmsgs($debugmsgs);
    perf_init();
    $perf_idx = perf_start('The rest');
  }

  // Do the dirty deed
  $res = $server->process($msg);

  // Add debugging info, if it's there
  if ($debugmsgs) {
    perf_stop($perf_idx);
    $times = perf_times();
    if (count($times) > 0) {
      $server->debugmsg("===times===\n" . serialize($times));
    }
    if ($server->debugstr) {
      // Should probably escape ">>\n", but live dangerously
      $res = "<<" . $server->debugstr . ">>\n$res";
    }
  }
  if ($debug) {
    $res = htmlspecialchars($res); 
    $res = "msg: <pre>$msg</pre>\nresponse: <pre>$res</pre>\n";
  }

} else {
  $res = file_get_contents($index_file);
}

// Here's the output
header("Content-Length: " . strlen($res));
echo $res;

// Copyright 2008-2009 Bill St. Clair
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
