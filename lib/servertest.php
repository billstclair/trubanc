<?php

  // servertest.php
  // Test code for the Trubanc server
  // Currently dangerous to run this on a real database, since it makes it inconsistent

require_once "server.php";
require_once "fsdb.php";
require_once "ssl.php";

$db = new fsdb("../trubancdb");
$ssl = new ssl();
$server = new server($db, $ssl, false, 'Trubanc');
$u = $server->u;                // utility instance
$tokenid = $server->tokenid;
$bankid = $server->bankid;
$t = $server->t;

$privkey = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMwfcmkk2coTuYAEbdZ5iXggObNPzbSiDnVtndZFe4/4Xg0IQPfp
Q04OkhWIftMy1OjFhGlBzzNzdW98KYwKMgsCAwEAAQJASAgk4LPPYz84q9NkS1ZS
S6Dbm8pipga2IXxQQaf9ZZ02vWpJR0tTlxq36Zl5P+aAbMck0AvHLgiawx0qWxRz
2QIhAPwyHhCeoZ972KcRi4AIVsWtkGfQsVpVbBOzuFmtAdU9AiEAzzOwvhW6az25
MyxD5VnbEhswT+lDnGAx/WSsHlPqaOcCIQCM0ac7/Heex9Z3ozJTsVRSWNHTRhJh
sGUCs01ytUnauQIgeZrNrRHVgeEM04K0KmPtFZhNZ2jwnFM8o4m1FmuLlJsCIQDc
9tCyRjE3Zj0tXfZL2n6DGeyAc0OsfdQn6V0tFPf6hg==
-----END RSA PRIVATE KEY-----
";
$pubkey = $ssl->privkey_to_pubkey($privkey);
$id = $ssl->pubkey_id($pubkey);

$privkey2 = "-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAK5kvoBZ9mw6xpt7M0M383q5/mhvzLTr1HUG9kr52aJyaV7OegEQ
ndsN45klFNvzD4slOuh2blg4ca7DuuARuYUCAwEAAQJBAI+aabwrWF268HxrsMSz
OA1hRvscxMZeQ66yMvF+WBYJIE873UDxUUMgvYJ0Dz6kg6u8BFBKcxWBCIP8e2Bi
p2kCIQDaH2fPpAd477Xad+BXUiiSqOgWrEIzMiAkZsE2Q+XgYwIhAMytXoq6eZar
+id+XvcTilxSVagqkC+549Og2HtsDP73AiEAteKEVVBJbt4svY1CxG3dKVaxmd5w
oXJF/TS2HsMFmFMCICZAYGLc5sxZ565p16WlaT5HxOpgygGhZAqxDMRENUmRAiAS
H3CnJ8Ul3VWvyL5hVjFDHYnD6n18+xqsnjeSQ4bRnQ==
-----END RSA PRIVATE KEY-----
";
$pubkey2 = $ssl->privkey_to_pubkey($privkey2);
$id2 = $ssl->pubkey_id($pubkey2);

function bankmsg() {
  global $bankid, $server, $ssl, $privkey;

  $args = func_get_args();
  $args = array_merge(array($bankid), $args);
  $msg = $server->u->makemsg($args);
  $sig = $ssl->sign($msg, $server->privkey);
  return "$msg:\n$sig";
}

function custmsg() {
  global $id, $server, $ssl, $privkey;

  $args = func_get_args();
  $args = array_merge(array($id), $args);
  $msg = $server->u->makemsg($args);
  $sig = $ssl->sign($msg, $privkey);
  return "$msg:\n$sig";
}

function custmsg2() {
  global $id2, $server, $ssl, $privkey2;

  $args = func_get_args();
  $args = array_merge(array($id2), $args);
  $msg = $server->u->makemsg($args);
  $sig = $ssl->sign($msg, $privkey2);
  return "$msg:\n$sig";
}

function process($msg) {
  global $server;

  echo "\n=== Msg ===\n$msg\n";
  echo "=== Response ===\n";
  $res = $server->process($msg);
  echo $res;
  return $res;
}

function getreq() {
  global $u;
  global $bankid;
  global $server;

  $msg = $server->process(custmsg('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) return false;
  return bcadd($args['req'], 1);
}

function getreq2() {
  global $u;
  global $bankid;
  global $server;

  $msg = $server->process(custmsg2('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) return false;
  return bcadd($args['req'], 1);
}

function getbankreq() {
  global $u;
  global $bankid;
  global $server;

  $msg = $server->process(bankmsg('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) return false;
  return bcadd($args['req'], 1);
}

function getbanktran() {
  global $u;
  global $bankid;
  global $server;

  $req = getbankreq();
  if (!$req) return $false;
  $msg = bankmsg('gettime', $bankid, $req);
  $msg = $server->process($msg);
  $args = $u->match_message($msg);
  if (is_string($args)) return false;
  return $args['time'];
}

function gettran() {
  global $u;
  global $bankid;
  global $server;

  $req = getreq();
  if (!$req) return $false;
  $msg = custmsg('gettime', $bankid, $req);
  $msg = $server->process($msg);
  $args = $u->match_message($msg);
  if (is_string($args)) return false;
  return $args['time'];
}

function gettran2() {
  global $u;
  global $bankid;
  global $server;

  $req = getreq2();
  if (!$req) return $false;
  $msg = custmsg2('gettime', $bankid, $req);
  $msg = $server->process($msg);
  $args = $u->match_message($msg);
  if (is_string($args)) return false;
  return $args['time'];
}

// Spend tokens from bank to $id to give him an account
if (!$db->contents($server->inboxkey($id)) &&
    !$db->contents($server->balancekey($id))) {
  $tran = getbanktran();
  $amt = 50;
  $spend = bankmsg('spend',$bankid,$tran,$id,$tokenid,$amt,"Welcome to Trubanc!");
  $msg = $db->get($server->assetbalancekey($bankid, $tokenid));
  $bal = $server->unpack_bankmsg($msg, $t->ATBALANCE, $t->BALANCE, $t->AMOUNT);
  echo "bal: $bal\n";
  $bal = bankmsg('balance',$bankid,$tran,$tokenid,$bal - $amt);
  process("$spend.$bal");
}

// Register $id, if not yet registered
if (!$server->pubkeydb->get($id)) {
  // Get the bankid. This command does not require an acount
  process(custmsg('bankid',$pubkey));
  process(custmsg("register",$bankid,$pubkey,"George Jetson"));
  process(custmsg('id',$bankid,$id));
}

//process(custmsg2("register",$bankid,$pubkey2,"Jane Jetson"));

$trans = $db->get($server->accttimekey($id));

// getinbox
$inbox = $db->contents($server->inboxkey($id));
if (count($inbox) > 0) {
  $req = getreq();
  if (!$req) echo "Couldn't get req\n";
  else {
    process(custmsg('getinbox', $bankid, $req));
    $trans = $db->get($server->accttimekey($id));
  }
}

$arr = explode(',', $trans);
$time = $arr[0];
echo "id1 trans: $trans, time: $time\n";

// Accept the id registration spend
$key = $server->inboxkey($id);
$inbox = $db->contents($key);
if (count($inbox) == 2) {
  sort($inbox, SORT_NUMERIC);
  $in0 = $inbox[0];
  $in1 = $inbox[1];
  $msg0 = $db->get("$key/" . $in0);
  $msg1 = $db->get("$key/" . $in1);
  $amt0 = $server->unpack_bankmsg($msg0, $t->INBOX, $t->SPEND, $t->AMOUNT);
  $amt1 = $server->unpack_bankmsg($msg1, $t->INBOX, $t->SPEND, $t->AMOUNT);
  if ($amt0 == 50 && $amt1 == -10) {
    $time0 = $server->unpack_bankmsg($msg0, $t->INBOX, $t->SPEND, $t->TIME);
    $time1 = $server->unpack_bankmsg($msg1, $t->INBOX, $t->SPEND, $t->TIME);
    $msg = custmsg($t->PROCESSINBOX, $bankid, $time, "$in0|$in1");
    $acc0 = custmsg($t->SPENDACCEPT, $bankid, $time0, $bankid);
    $acc1 = custmsg($t->SPENDACCEPT, $bankid, $time1, $bankid);
    $bal = custmsg($t->BALANCE, $bankid, $time, $tokenid, 39);
    $acctbals = array($t->MAIN => array($t->tokenid => $bal));
    $array = $u->balancehash($db, $id, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg($t->BALANCEHASH, $bankid, $time, $count, $hash);
    process("$msg.$acc0.$acc1.$bal.$balhash");
  }
}

// Spend tokens from bank to $id2 to give him an account
if (!$db->contents($server->inboxkey($id2)) &&
    !$db->contents($server->balancekey($id2))) {
  $tran = getbanktran();
  $amt = 50;
  $spend = bankmsg('spend',$bankid,$tran,$id2,$tokenid,$amt,"Welcome to Trubanc!");
  $msg = $db->get($server->assetbalancekey($bankid, $tokenid));
  $bal = $server->unpack_bankmsg($msg, $t->ATBALANCE, $t->BALANCE, $t->AMOUNT);
  echo "bal: $bal\n";
  $bal = bankmsg('balance',$bankid,$tran,$tokenid,$bal - $amt);
  process("$spend.$bal");
}

// Register $id2, if not yet registered
if (!$server->pubkeydb->get($id2)) {
  // Get the bankid. This command does not require an acount
  process(custmsg2('bankid',$pubkey2));
  process(custmsg2("register",$bankid,$pubkey2,"Jane Jetson"));
  process(custmsg2('id',$bankid,$id2));
}

$trans = $db->get($server->accttimekey($id2));

// getinbox
$inbox = $db->contents($server->inboxkey($id2));
if (count($inbox) > 0) {
  $req = getreq2();
  if (!$req) echo "Couldn't get req\n";
  else {
    process(custmsg2('getinbox', $bankid, $req));
    $trans = $db->get($server->accttimekey($id2));
  }
}

$arr = explode(',', $trans);
$time = $arr[0];
echo "id2 trans: $trans, time: $time\n";

// Accept the id2 registration spend
$key = $server->inboxkey($id2);
$inbox = $db->contents($key);
if (count($inbox) == 2) {
  sort($inbox, SORT_NUMERIC);
  $in0 = $inbox[0];
  $in1 = $inbox[1];
  $msg0 = $db->get("$key/$in0");
  $msg1 = $db->get("$key/$in1");
  $amt0 = $server->unpack_bankmsg($msg0, $t->INBOX, $t->SPEND, $t->AMOUNT);
  $amt1 = $server->unpack_bankmsg($msg1, $t->INBOX, $t->SPEND, $t->AMOUNT);
  if ($amt0 == 50 && $amt1 == -10) {
    $time0 = $server->unpack_bankmsg($msg0, $t->INBOX, $t->SPEND, $t->TIME);
    $time1 = $server->unpack_bankmsg($msg1, $t->INBOX, $t->SPEND, $t->TIME);
    $msg = custmsg2($t->PROCESSINBOX, $bankid, $time, "$in0|$in1");
    $acc0 = custmsg2($t->SPENDACCEPT, $bankid, $time0, $bankid);
    $acc1 = custmsg2($t->SPENDACCEPT, $bankid, $time1, $bankid);
    $bal = custmsg2($t->BALANCE, $bankid, $time, $tokenid, 39);
    $acctbals = array($t->MAIN => array($tokenid => $bal));
    $array = $u->balancehash($db, $id2, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg2($t->BALANCEHASH, $bankid, $time, $count, $hash);
    process("$msg.$acc0.$acc1.$bal.$balhash");
  }
}

// Create an asset
$scale = 7;
$precision = 3;
$assetname = "George Fake Goldgrams";
$assetid = $server->u->assetid($id, $scale, $precision, $assetname);
if (!$server->is_asset($assetid)) {
  $req = getreq();
  if (!$req) echo "Couldn't get req for asset creation\n";
  else {
    process(custmsg('gettime', $bankid, $req));
    $time = $db->get($server->accttimekey($id));
    $process = custmsg('asset', $bankid, $assetid, $scale, $precision, $assetname);
    $bal1 = custmsg('balance', $bankid, $time, $tokenid, 37);
    $bal2 = custmsg('balance', $bankid, $time, $assetid, -1);
    $acctbals = array($t->MAIN => array($tokenid => $bal1,
                                        $assetid => $bal2));
    $array = $u->balancehash($db, $id, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg($t->BALANCEHASH, $bankid, $time, $count, $hash);
    process("$process.$bal1.$bal2.$balhash");
  }
}

// Regular spend
if ($server->assetbalance($id, $assetid) == -1) {
  $tran = gettran();
  $amt = 1000;
  $spend = custmsg('spend',$bankid,$tran,$id2,$assetid,$amt,"Here's a gram of my new gold currency");
  $fee = custmsg('tranfee',$bankid,$tran,$tokenid,2);
  $bal1 = custmsg('balance',$bankid,$tran,$assetid,-1 - $amt);
  $bal2 = custmsg('balance',$bankid,$tran,$tokenid,35);
  $array = $server->outboxhash($id, $spend);
  $hash = $array[$t->HASH];
  $hashcnt = $array[$t->COUNT];
  $outboxhash = custmsg('outboxhash', $bankid, $tran, $hashcnt, $hash);
  $acctbals = array($t->MAIN => array($tokenid => $bal1,
                                      $assetid => $bal2));
  $array = $u->balancehash($db, $id, $server, $acctbals);
  $hash = $array[$t->HASH];
  $count = $array[$t->COUNT];
  $balhash = custmsg($t->BALANCEHASH, $bankid, $tran, $count, $hash);
  process("$spend..$fee.$bal1.$bal2.$outboxhash.$balhash");
}

// spend|accept
$key = $server->inboxkey($id2);
$inbox = $db->contents($key);
if (count($inbox) == 1) {
  $in = $inbox[0];
  $msg = $db->get("$key/$in");
  $amt = $server->unpack_bankmsg($msg, $t->INBOX, $t->SPEND, $t->AMOUNT);
  if ($amt == 1000) {
    $time = $server->unpack_bankmsg($msg, $t->INBOX, $t->SPEND, $t->TIME);
    $tran = gettran2();
    $process = custmsg2('processinbox', $bankid, $tran, $in);
    $accept = custmsg2('spend|accept', $bankid, $time, $id, "Thanks for all the fish");
    $bal1 = custmsg2('balance', $bankid, $tran, $assetid, 1000);
    $bal2 = custmsg2('balance', $bankid, $tran, $tokenid, 38);
    $acctbals = array($t->MAIN => array($assetid => $bal1,
                                        $tokenid => $bal2));
    $array = $u->balancehash($db, $id2, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg2($t->BALANCEHASH, $bankid, $tran, $count, $hash);
    process("$process.$accept.$bal1.$bal2.$balhash");
  }
}

// Acknowledge spend|accept (tokens returned)
$key = $server->outboxkey($id);
$outbox = $db->contents($key);
$key = $server->inboxkey($id);
$inbox = $db->contents($key);
if (count($inbox) == 1 && count($outbox) == 1) {
  $out = $outbox[0];
  $in = $inbox[0];
  $msg = $db->get("$key/$in");
  $args = $server->unpack_bankmsg($msg, $t->INBOX, $t->SPENDACCEPT);
  if (is_array($args)) {
    $tran = gettran();
    $process = custmsg('processinbox', $bankid, $tran, $in);
    $bal = custmsg('balance', $bankid, $tran, $tokenid, 37);
    $array = $server->outboxhash($id, false, array($out));
    $hash = $array[$t->HASH];
    $hashcnt = $array[$t->COUNT];
    $outboxhash = custmsg('outboxhash', $bankid, $tran, $hashcnt, $hash);
    $acctbals = array($t->MAIN => array($tokenid => $bal));
    $array = $u->balancehash($db, $id, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg($t->BALANCEHASH, $bankid, $tran, $count, $hash);
    process("$process.$bal.$outboxhash.$balhash");
  }
}

// Regular spend
if ($server->assetbalance($id, $assetid) == -1001 &&
    $server->assetbalance($id, $tokenid) == 37) {
  $tran = gettran();
  $amt = 500;
  $spend = custmsg('spend',$bankid,$tran,$id2,$assetid,$amt,"Another half a gram");
  $fee = custmsg('tranfee',$bankid,$tran,$tokenid,2);
  $bal1 = custmsg('balance',$bankid,$tran,$assetid,-1001 - $amt);
  $bal2 = custmsg('balance',$bankid,$tran,$tokenid,35);
  $array = $server->outboxhash($id, $spend);
  $hash = $array[$t->HASH];
  $hashcnt = $array[$t->COUNT];
  $outboxhash = custmsg('outboxhash', $bankid, $tran, $hashcnt, $hash);
  $acctbals = array($t->MAIN => array($tokenid => $bal1,
                                      $assetid => $bal2));
  $array = $u->balancehash($db, $id, $server, $acctbals);
  $hash = $array[$t->HASH];
  $count = $array[$t->COUNT];
  $balhash = custmsg($t->BALANCEHASH, $bankid, $tran, $count, $hash);
  process("$spend..$fee.$bal1.$bal2.$outboxhash.$balhash");
}

// spend|reject
$key = $server->inboxkey($id2);
$inbox = $db->contents($key);
if (count($inbox) == 1) {
  $in = $inbox[0];
  $msg = $db->get("$key/$in");
  $amt = $server->unpack_bankmsg($msg, $t->INBOX, $t->SPEND, $t->AMOUNT);
  if ($amt == 500) {
    $time = $server->unpack_bankmsg($msg, $t->INBOX, $t->SPEND, $t->TIME);
    $tran = gettran2();
    $process = custmsg2('processinbox', $bankid, $tran, $in);
    $reject = custmsg2('spend|reject', $bankid, $time, $id, "I don't want your money");
    $bal = custmsg2('balance', $bankid, $tran, $tokenid, 40);
    $acctbals = array($t->MAIN => array($tokenid => $bal));
    $array = $u->balancehash($db, $id2, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg2($t->BALANCEHASH, $bankid, $tran, $count, $hash);
    process("$process.$reject.$bal.$balhash");
  }
}

// Acknowledge spend|reject
$key = $server->outboxkey($id);
$outbox = $db->contents($key);
$key = $server->inboxkey($id);
$inbox = $db->contents($key);
if (count($inbox) == 1 && count($outbox) == 1) {
  $out = $outbox[0];
  $in = $inbox[0];
  $msg = $db->get("$key/$in");
  $args = $server->unpack_bankmsg($msg, $t->INBOX, $t->SPENDREJECT);
  if (is_array($args)) {
    $tran = gettran();
    $process = custmsg('processinbox', $bankid, $tran, $in);
    $bal = custmsg('balance', $bankid, $tran, $assetid, -1001);
    $array = $server->outboxhash($id, false, array($out));
    $hash = $array[$t->HASH];
    $hashcnt = $array[$t->COUNT];
    $outboxhash = custmsg('outboxhash', $bankid, $tran, $hashcnt, $hash);
    $acctbals = array($t->MAIN => array($assetid => $bal));
    $array = $u->balancehash($db, $id, $server, $acctbals);
    $hash = $array[$t->HASH];
    $count = $array[$t->COUNT];
    $balhash = custmsg($t->BALANCEHASH, $bankid, $tran, $count, $hash);
    process("$process.$bal.$outboxhash.$balhash");
  }
}

if (false) {
  if ($req = getreq()) {
    process(custmsg('getbalance', $bankid, $req));
  }
  if ($req = getreq()) {
    process(custmsg('getbalance', $bankid, $req, 'main'));
  }
  if ($req = getreq()) {
    process(custmsg('getbalance', $bankid, $req, 'main', $tokenid));
  }
  // Expect empty return. No 'froboz' account
  if ($req = getreq()) {
    process(custmsg('getbalance', $bankid, $req, 'froboz'));
  }
  // Expect empty return. No 'froboz' account
  if ($req = getreq()) {
    process(custmsg('getbalance', $bankid, $req, 'froboz', $tokenid));
  }
  // Should fail, due to bad $req
  process(custmsg('getbalance', $bankid, $req, 'froboz', $tokenid));
}

if (false) {
  if ($req = getreq()) {
    process(custmsg('getoutbox', $bankid, $req));
  }
  // Error for old req
  process(custmsg('getoutbox', $bankid, $req));
}

if (false) {
  if ($req = getreq()) {
    process(custmsg('getasset', $bankid, $req, $tokenid));
  }
  // Should fail, due to bad req
  process(custmsg('getasset', $bankid, $req, $tokenid));
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
