<?php

  // index.php
  // Trubanc main page

// Define $dbdir, $bank_name, $index_file, $bankurl
if (file_exists("settings.php")) require_once "settings.php";

if (!properly_configured_p()) return;

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

// Test for proper configuration. Return true if so.
// If not, output an information page, and return false.
function properly_configured_p() {
  global $index_file, $dbdir, $bank_name;
  global $error;

  $dir = realpath(dirname($_SERVER['SCRIPT_FILENAME']));

  if (!file_exists('settings.php')) {
    $error = "The file 'settings.php' was not found in $dir<br>" .
             "Copy settings.php.tmpl to settings.php, and change the variables.";
  } elseif (!$index_file) {
    $error = 'The $index_file variable is not set in settings.php';
  } elseif (!file_exists($index_file)) {
    $error = "\$index_file = '$index_file', but that file does not exist";
  } elseif (!$dbdir) {
    $error = 'The $dbdir variable is not set in settings.php';
  } elseif (!is_dir($dbdir)) {
    $error = "\$dbdir, '$dbdir', is not a directory";
  } elseif (!is_writable($dbdir)) {
    $error = "The \$dbdir directory, '$dbdir', is not writable";
  } elseif (!$bank_name) {
    $error = 'The $bank_name variable is not set in settings.php';
  }

  if ($error) {
?>
<html>
<head>
<title>Trubanc Server Misconfigured</title>
</head>
<head>
This Trubanc server is misconigured. Read the
<a href="INSTALL">INSTALL</a> directions.
<p>
<? echo $error; ?>
</head>
</html>
<?      
    return false;
  }

  return true;  
}

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
