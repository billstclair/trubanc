<?PHP

  // Toggle client debugging output

if ($_COOKIE['debug']) {
  setcookie('debug', false);
  $msg = "Debugging disabled";
} else {
  if (setcookie('debug', 'debug')) $msg = "Debugging enabled";
  else $msg = "Can't enable debugging. Need cookies.";
}

?>
<html>
<head>
<title>Toggle Trubanc Client Debugging</title>
</head>
<body>
<? echo $msg; ?>
</body>
</html>

