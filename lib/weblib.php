<?php

  // Shared functions for top-level web forms

// If $ssl_url is true, and access is NOT via "https", forward to the same
// URI at "https://$ssl_url".
function maybe_forward_to_ssl($ssl_domain) {
  if (!$ssl_domain) return;
  if ($_SERVER["HTTPS"] == "on") return;
  $url = "https://$ssl_domain";
  if (substr($url, -1) == '/') $url = substr($url, 0, -1);
  $url .= $_SERVER["REQUEST_URI"];
  header("Location: $url");
  // In case headers were already sent
  echo "Click here: <a href=\"$url\">$url</a>";
  die();
}

// Test for proper configuration. Return true if so.
// If not, output an information page, and return false.
function die_unless_server_properly_configured() {
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
<?php echo $error; ?>
</head>
</html>
<?php      
    die();
  }
}

// Test for proper configuration. Return true if so.
// If not, output an information page, and return false.
// Returns error message instead of dying, if $return_error is true
// Otherwise, returns false.
function die_unless_client_properly_configured($return_error=false) {
  global $dbdir, $template_file;
  global $error;

  $dir = realpath(dirname($_SERVER['SCRIPT_FILENAME']));

  if (!file_exists('settings.php')) {
    $error = "The file 'settings.php' was not found in $dir<br>" .
             "Copy settings.php.tmpl to settings.php, and change the variables.";
  } elseif (!$dbdir) {
    $error = 'The $dbdir variable is not set in settings.php';
  } elseif (!is_dir($dbdir)) {
    $error = "\$dbdir, '$dbdir', is not a directory";
  } elseif (!is_writable($dbdir)) {
    $error = "The \$dbdir directory, '$dbdir', is not writable";
  } elseif (!file_exists($template_file)) {
    $error = "The template file, $template_file, does not exist";
  }

  if ($error) {
    if ($return_error) return $error;
?>
<html>
<head>
<title>Trubanc Client Misconfigured</title>
</head>
<head>
Your Trubanc client is misconigured. Read the <a
href="../INSTALL">INSTALL</a> directions.
<p>
<?php echo $error ?>
</head>
</html>
<?php      
    die();
  }

  return false;

}
