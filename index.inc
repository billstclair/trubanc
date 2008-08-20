<html>
<head>
<title>Trubanc</title>
<link rel="shortcut icon" href="site-icon.png"/>
</head>
<body>
<center>
<h1>Trubanc</h1>
<p>
<img src="trubanc-logo.jpg" alt="Truebanc" width="376" height="355"/>
<p>
<table width="75%"><tr><td>
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
</td></tr></table>
<p>
<a href="plain-english.html">Trubanc in Plain English</a>
<p>
<table width="75%"><tr><td>

This page is a live server. Invoke it as
"http://trubanc.com/?msg=&lt;msg>", and it will interpret &lt;msg> as
a server request, and return the result. For example,
<a href="./?debug=true&msg=(bc50c4fd9c228a21f64d34ca644a46c1fe8520e4%2Cbankid%2C-----BEGIN+PUBLIC+KEY-----%0AMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMwfcmkk2coTuYAEbdZ5iXggObNPzbSi%0ADnVtndZFe4%2F4Xg0IQPfpQ04OkhWIftMy1OjFhGlBzzNzdW98KYwKMgsCAwEAAQ%3D%3D%0A-----END+PUBLIC+KEY-----%0A)%3A%0AsLJ9GqFjZ61fq%2FbDFL6rxpY3w2s5dWIAXJCvPKQTPEkrG%2F2I1fwxBfugBmn%2FiPwa%0AjCRtnFDnrn7Mv%2BUY%2BSH4yw%3D%3D">
click here</a> to send a "bankid" request, with debugging enabled to
make it easy to see. I'm working on a web client, which I'll link to here when it's ready to test.

</td></tr></table>
<p>
You may view code in progress <a href="viewtext.php">here</a>.
<br/>
To discuss, join <a href="irc://irc.freenode.net/#Trubanc">#Trubanc</a> on irc.freenode.net.
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
