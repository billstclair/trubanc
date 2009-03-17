<?php
require_once "lib/ssl.php";

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

$keysize = mq($_REQUEST['keysize']);
$passphrase = mq($_REQUEST['passphrase']);

?>
<html>
<head>
<title>Public Key Forge</title>
</head>
<body>
<?
if ($keysize && is_numeric($keysize)) {

$ssl = new ssl();
$privkey = $ssl->make_privkey($keysize, $passphrase);
$pubkey = $ssl->privkey_to_pubkey($privkey, $passphrase);
$id = $ssl->pubkey_id($pubkey);
  
echo "ID: $id<br>\n"; 
echo "<pre>\n$pubkey</pre>\n";
echo "<pre>\n$privkey</pre>\n";
}

if (!$keysize || !is_numeric($keysize)) $keysize = 512;

function hsc($x) {
  return htmlspecialchars($x);
}

?>
<form method="post">
  <table>
  <tr>
  <td>Key size:</td>
  <td><input type="text" name="keysize" value="<?php echo hsc($keysize); ?>"/></td>
  </tr><tr>
  <td>Passphrase:</td>
  <td><input type="password" name="passphrase" value=""/></td>
  </tr><tr>
  <td>&nbsp;</td>
  <td><input type="submit" value="Generate"/></td>
  </tr>
  </table>
</form>
</body>
</html>
