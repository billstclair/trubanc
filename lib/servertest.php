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

process(custmsg('bankid',$pubkey));
//process(custmsg("register",$bankid,$pubkey,"George Jetson"));
//process(custmsg2("register",$bankid,$pubkey2,"Jane Jetson"));
//process(custmsg('id',$bankid,$id));

// getinbox
if (false) {
  $msg = process(custmsg('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) echo "Failure parsing or matching: $args\n";
  else {
    $req = bcadd($args['req'], 1);
    //process(custmsg('gettime', $bankid, $req));
    //process(custmsg('getfees', $bankid, $req));
    process(custmsg('getinbox', $bankid, $req));
  }
}

// spend
if (false) {
  $spend = custmsg('spend',$bankid,4,$id2,$server->tokenid,5,"Have some fish!");
  $fee = custmsg('tranfee',$bankid,4,$server->tokenid,2);
  $bal = custmsg('balance',$bankid,4,$server->tokenid,13);
  $hash = $server->outboxhash($id, 4, $spend);
  $hash = custmsg('outboxhash', $bankid, 4, $hash);
  $db->put($server->accttimekey($id), 4);
  process("$spend.$fee.$bal.$hash");
}

// spend|accept
if (false) {
  $db->put($server->accttimekey($id2), 7);
  $process = custmsg2('processinbox', $bankid, 7, 6);
  $accept = custmsg2('spend|accept', $bankid, 4, $id, "Thanks for all the fish");
  $bal = custmsg2('balance', $bankid, 7, $tokenid, 25);
  process("$process.$accept.$bal");
}

// Acknowledge spend|accept (tokens returned)
if (false) {
  $msg = process(custmsg('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) echo "Failure parsing or matching: $args\n";
  else {
    $req = bcadd($args['req'], 1);
    process(custmsg('gettime', $bankid, $req));
    $time = $db->get($server->accttimekey($id));
    $process = custmsg('processinbox', $bankid, $time, 6);
    $hash = $server->outboxhash($id, $time, false, array(4));
    $outboxhash = custmsg('outboxhash', $bankid, $time, $hash);
    $bal = custmsg('balance', $bankid, $time, $tokenid, 15);
    process("$process.$outboxhash.$bal");
  }
}

// spend|reject
if (false) {
  $db->put($server->accttimekey($id2), 7);
  $process = custmsg2('processinbox', $bankid, 7, 6);
  $accept = custmsg2('spend|reject', $bankid, 4, $id, "No thanks. I don't eat fish");
  $bal = custmsg2('balance', $bankid, 7, $tokenid, 22);
  process("$process.$accept.$bal");
}

// Acknowledge spend|reject (tokens given to $id2)
if (false) {
  $msg = process(custmsg('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) echo "Failure parsing or matching: $args\n";
  else {
    $req = bcadd($args['req'], 1);
    process(custmsg('gettime', $bankid, $req));
    $time = $db->get($server->accttimekey($id));
    $process = custmsg('processinbox', $bankid, $time, 6);
    $hash = $server->outboxhash($id, $time, false, array(4));
    $outboxhash = custmsg('outboxhash', $bankid, $time, $hash);
    $bal = custmsg('balance', $bankid, $time, $tokenid, 18);
    process("$process.$outboxhash.$bal");
  }
}

// Create an asset
if (false) {
  $scale = 7;
  $precision = 3;
  $assetname = "Bill Fake Goldgrams";
  $assetid = $server->u->assetid($id, $scale, $precision, $assetname);
  $msg = process(custmsg('getreq', $bankid));
  $args = $u->match_message($msg);
  if (is_string($args)) echo "Failure parsing or matching: $args\n";
  else {
    $req = bcadd($args['req'], 1);
    process(custmsg('gettime', $bankid, $req));
    $time = $db->get($server->accttimekey($id));
    $process = custmsg('asset', $bankid, $assetid, $scale, $precision, $assetname);
    $bal1 = custmsg('balance', $bankid, $time, $tokenid, 18);
    $bal2 = custmsg('balance', $bankid, $time, $assetid, -1);
    process("$process.$bal1.$bal2");
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

?>
