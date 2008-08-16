<?php

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

$msg = mq($_REQUEST['msg']);
$debug = mq($_REQUEST['debug']);

if ($msg) {

  require_once "settings.php";
  require_once "lib/fsdb.php";
  require_once "lib/ssl.php";
  require_once "lib/server.php";

  $db = new fsdb($dbdir);
  $ssl = new ssl();
  $server = new server($db, $ssl, false, 'Trubanc');
  if ($debug) {
    echo "msg: <pre>$msg</pre>\n";
    echo "<pre>";
  }
  echo $server->process($msg);
  if ($debug) {
    echo "</pre>\n";
  }

} else {
?>
<html>
<head>
<title>Trubanc.com</title>
</head>
<body>
<center>
<h1>Trubanc.com</h1>
<p>
<img src="trubanc-logo.jpg" alt="Truebanc" width="376" height="355"/>
<p>
<a href="http://Trubanc.com/">Trubanc</a> is an anonymous,
digitally-signed vault and trading system. Like
<a href="https://loom.cc/">Loom</a>, it allows anyone to issue assets
(digital currencies). Unlike Loom, which relies entirely on (very
good) obscurity for security, Trubanc's digital signatures allow the
bank and the customer to prove to each other that they agreed at a
particular time on their balances. It does this while allowing
destruction of transaction history for closed trades. Trubanc will
initially provide server-based trading. Eventually, it will provide
digital checks and bearer certificates. These, however, WILL require
permanent storage of transaction history.
<p>
<a href="plain-english.html">Trubanc in Plain English</a>
<p>
You may view unfinished code in progress <a href="viewtext.php">here</a>.
</center>
Git repository at <a href="http://repo.or.cz/w/Trubanc.git">repo.or.cz/w/Trubanc.git</a>.<br>
To download the code to the "trubanc" subdir of pwd:
<blockquote><code>
git clone git://repo.or.cz/Trubanc.git trubanc
</code></blockquote>
<center>
<p style="font-size: 75%;">Copyright &copy; Bill St. Clair, 2008. All rights reserved.</p>
</center>
</body>
</html>
<?
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
