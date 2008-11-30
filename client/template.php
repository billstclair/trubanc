<?PHP

  // Template for client screens
  // $title - Title string, default: A Trubanc Web Client
  // $bankname - name of bank, default "Trubanc"
  // $menu - html to go to the right of the logo
  // $body - Body html to include, default: template identification text
  // $onload - script to run onload, default: nothing

if (!$title) $title = "A Trubanc Web Client";
if (!$bankname) $bankname = "Trubanc";
if (!$menu) $menu = '';
if (!$body) $body = 'This is the template for Trubanc web client pages';

?>
<html>
<head>
<title><? echo $title; ?></title>
</head>
<body<? if ($onload) echo " onload='$onload'"; ?>>
<p>
<img style="vertical-align: middle;" src="../trubanc-logo-50x47.jpg" alt="Trubanc" width="50" height="47"/>
<b><? echo $bankname; ?></b>
<? if ($menu) echo "&nbsp;&nbsp;$menu"; ?>
</p>
<? echo $bankline; ?>
<? echo idcode(); ?>
<? echo $body; ?>
</body>
</html>
