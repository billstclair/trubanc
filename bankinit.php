<?php

  // Initialize the server database and create a client account for the bank

require_once "lib/weblib.php";

// Define $dbdir, $bank_name, $index_file, $bankurl, $ssl_domain
if (file_exists("settings.php")) require_once "settings.php";

die_unless_server_properly_configured();
maybe_forward_to_ssl($ssl_domain);

pagehead();
doit();
pagetail();

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

function mqreq($x) {
  return mq($_REQUEST[$x]);
}

$enabledebug = false;

$debug = '';

function appenddebug($x) {
  global $debug;
  $debug .= $x;
}

function hsc($x) {
  return htmlspecialchars($x);
}

function trimsig($x) {
  $x = trim($x);
  $x = str_replace("\r", "", $x);
  $x = str_replace("\n", "", $x);
  return $x;
}

function doit() {
  global $dbdir, $bank_name, $bankurl;
  global $template_file;

  $init = mqreq('init');
  $initadmin = mqreq('initadmin');
  $drawadmin = mqreq('drawadmin');
  $passphrase = mqreq('passphrase');
  $verification = mqreq('verification');
  $bankpass = mqreq('bankpass');
  $name = mqreq('name');
  $random = mqreq('random');
  $sig = mqreq('sig');

  require_once "lib/fsdb.php";
  require_once "lib/ssl.php";
  require_once "lib/server.php";

  $ssl = new ssl();
  $db = new fsdb($dbdir);

  if ($init) {
    if (!$passphrase) $error = "Passphrase must be entered";
    elseif ($passphrase != $verification) {
      $error = "Passphrase doesn't match verification. Try again.";
    } else {
      $server = new server($db, $ssl, false, $bank_name, $bankurl);
      $t = $server->t;
      $bankid = $server->bankid;
      $tokenid = $server->tokenid;
      $msg = "(0,bankid,0):0";
      $res = $server->process($msg);
      $args = $server->unpack_bankmsg($res, $t->BANKID);
      if (is_string($args)) $error = "Error testing server: $args";
      else {
        $bal = $db->get("account/$bankid/balance/main/$tokenid");
        if (!$bal) $error = "Bank has no token balance";
        else {
          $args = $server->unpack_bankmsg($bal, $t->ATBALANCE, $t->BALANCE);
          if (is_string($args)) $error = "On parsing bank token balance: $args";
        }
      }
    }

    // Initialize client
    if (!$error) {
      $dbdir = '';
      if (file_exists('client/settings.php')) require_once "client/settings.php";
      $dbdir = "client/$dbdir";
      $template_file = "client/$template_file";
      $error = die_unless_client_properly_configured(true);
      if (!$error) {
        require_once "lib/client.php";
        $clientdb = new fsdb("$dbdir");
        $client = new client($clientdb, $ssl);

        if ($enabledebug) $client->showprocess = 'appenddebug';

        $hash = $client->passphrasehash($passphrase);
        if ($clientdb->get("privkey/$hash") ||
            $clientdb->get("account/$bankid/bank/$bankid/req")) {
          $error = $client->login($passphrase);
          if ($error || $bankid != $client->id) {
            $error = "Passphrase not for bank account";
          }
        } else {
          $privkey = $db->get('privkey');
          $pk = $ssl->load_private_key($privkey);
          if (!$pk) $error = "Can't load bank private key";
          else {
            openssl_pkey_export($pk, $privkey, $passphrase);
            openssl_free_key($pk);
            $error = $client->verifybank($bankurl, $bankid);
            if (!$error) {
              $error = $client->newuser($passphrase, $privkey);
            }
          }
        }
      }
    }
    if (!$error) {
      $drawadmin = true;
      $bankpass = $passphrase;
      require_once "lib/LoomRandom.php";
      $random = new LoomRandom();
      $random = $random->random_id();
      $sig = trimsig($ssl->sign($random, $db->get('privkey')));
    }
  } elseif ($initadmin) {
    if (!$passphrase) $error = "Passphrase must be entered";
    elseif ($passphrase != $verification) {
      $error = "Passphrase doesn't match verification. Try again.";
    } else {
      // This requires you to get here by knowing the bank passphrase
      $sig = trimsig($sig);
      $newsig = trimsig($ssl->sign($random, $db->get('privkey')));
      if ($newsig != $sig) {
        echo "<p>Hacking attempt foiled!</p>";
        echo "Lens: " . strlen($sig) . ", " . strlen($newsig) . "<br>\n";
        echo "<pre>\"$sig\"\n\n\"$newsig\"</pre>";
        return;
      }

      if (!$server) $server = new server($db, $ssl, false, $bank_name, $bankurl);
      $t = $server->t;
      $bankid = $server->bankid();
      $tokenid = $server->tokenid;

      if (file_exists('client/settings.php')) require_once "client/settings.php";
      $dbdir = "client/$dbdir";
      $template_file = "client/$template_file";
      $error = die_unless_client_properly_configured(true);
      if (!$error) {
        require_once "lib/client.php";
        $clientdb = new fsdb("$dbdir");
        $client = new client($clientdb, $ssl);

        if ($enabledebug) $client->showprocess = 'appenddebug';

        $hash = $client->passphrasehash($passphrase);
        if (!$clientdb->get("privkey/$hash")) {
          // Create the new account
          $error = $client->newuser($passphrase);
        } else {
          $error = $client->login($passphrase);
        }
        if (!$error) {
          $id = $client->id;
          if ($clientdb->get("account/$id/bank/$bankid/req")) {
            $error = 'Account already exists for that passphrase. ' .
                     'Use the <a href="client/">client interface</a> to administer.';
          } else {
            $error = $client->login($bankpass);
            if (!$error) $error = $client->addbank($bankurl);
            if (!$error) $error = $client->setbank($bankid);
            if (!$error) $error = $client->spend($id, $tokenid, "10000");
            if ($error) $error = "While spending tokens from bank: $error";
          }
          if (!$error) {
            $error = $client->login($passphrase);
            if (!$error) $error = $client->addbank($bankurl, $name);
            if (!$error) {
?>
<p>Your bank is now ready for business. You may now login as administrator in the
<a href="client/">Client interface</a>, accept your initial tokens from
the bank, and start inviting customers.</p>
<?php
              return;
            }
          }
        }
      }
    }
  }

  if (!$error) $error = "&nbsp;";

  if ($drawadmin) {
?>
<p>Congratulations! You have succesfully initialized your bank.</p>

<p>Use the form below to create an administration account for your bank.
Use the bank's account only to spend usage tokens to the administration account.
Use the administration account to mint coupons, and to conduct other
bank business.</p>

<p style="color: red;"><?php echo $error; ?></p>
<form method="post" action="./bankinit.php" autocomplete="off">
<input type="hidden" name="drawadmin" value="true"/>
<input type="hidden" name="bankpass" value="<?php echo $bankpass; ?>"/>
<input type="hidden" name="random" value="<?php echo hsc($random); ?>"/>
<input type="hidden" name="sig" value="<?php echo hsc($sig); ?>"/>
<table>
<tr>
<td><b>Admin Passphrase:</b></td>
<td><input type="password" name="passphrase" size="50"/></td>
</tr>
<tr>
<td><b>Verification:</b></td>
<td><input type="password" name="verification" size="50"/></td>
</tr>
<tr>
<tr>
<td><b>Name (optional):</b></td>
<td><input type="text" name="name" size="40" value="<?php echo $name; ?>"/></td>
</tr>
<tr>
<td></td>
<td><input type="submit" name="initadmin" value="Create Admin Account"/></td>
</tr>
</table>
</form>
<?php
    return;
  }

?>
<p style="color: red;"><?php echo $error; ?></p>
<form method="post" action="./bankinit.php" autocomplete="off">
<table>
<tr>
<td><b>Bank Passphrase:</b></td>
<td><input type="password" name="passphrase" size="50"/></td>
</tr>
<tr>
<td><b>Verification:</b></td>
<td><input type="password" name="verification" size="50"/></td>
</tr>
<tr>
<td></td>
<td><input type="submit" name="init" value="Initialize"/></td>
</tr>
</table>
</form>
<?php
}

function pagehead() {
?>
<html>
<head>
<title>Trubanc Bank Initialization</title>
</title>
</head>
<body onload="document.forms[0].passphrase.focus()">
<p>This page initializes your bank, creates the bank private key,
and creates a client account for the bank.</p>
<?php
}

function pagetail() {
  global $debug;

 if ($debug) echo "<b>=== Debug log ===</b><br/><pre>$debug</pre>\n";
?>
</body>
</html>
<?php
}
