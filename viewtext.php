<?php

  // Simple file viewer
  // Allows viewing of files with word wrap.

function mq($x) {
  if (get_magic_quotes_gpc()) return stripslashes($x);
  else return $x;
}

$file = mq($_GET['file']);
$title = mq($_GET['title']);
$numbers = mq($_GET['numbers']);
$search = mq($_GET['search']);

$file = trim($file);

if ($title == '') $title = $file;

$files = explode("\n", file_get_contents('viewtext.txt'));

foreach($files as $idx => $line) {
  if ($line != '') {
    $parts = explode('|', $line);
    $name = $parts[0];
    $label = '';
    if (count($parts) > 1) $label = " - " . $parts[1];
    if ($file != '') $files[$idx] = $name;
    else {
      $files[$idx] = "<input type='radio' name='file' value='$name'/> <a href=\"?file=$name\">$name</a>$label<br/>";
      if (count($files) > ($idx+2) && $files[$idx+1] == '') {
        $files[$idx] .= "<br/>";
      }
    }
  }
}

if ($file == '') {
  if ($title == '') $title = "Text Viewer";
} else {
  if (!in_array($file, $files)) {
    echo "Thought you could access some random file, didn't you. Not!";
    return;
  }

  $text = htmlspecialchars(file_get_contents($file));

  // Do search, if requested
  if ($search != '') {
    $i = 1;
    // Escape special chars in the search string
    $search = preg_replace("=([/\\\\^$.[\\]|()?*+{}])=", '\\\\$1', $search);
    // Now replace instances of the search string
    $text = preg_replace_callback('/' . $search . '/i', "searchBody", $text);
    // Make the last match loop around
    $text = str_replace('href="#' . $i . '">', 'href="#1">', $text);
  }

  // Add line numbers, if requested
  if ($numbers != '') {
    $lines = explode("\n", $text);
    $cnt = count($lines);
    $digits = strlen($cnt);
    $format = "%0" . $digits . 'd';
    $i = 1;
    foreach ($lines as $idx => $line) {
      if ($i < $cnt || $line != '') {
        $lines[$idx] = '<a name="line' . $i . '" href="#line' . $i . '">' .
          sprintf($format, $i) . '</a> ' . $line;
      }
      $i++;
    }
    $text = implode("\n", $lines);
  }

  // Add line breaks
  $text = str_replace("\n", "<br>\n", $text);

  // Make spaces non-breaking
  $text = str_replace(" ", "&nbsp;", $text);

  // And change the non-duplicated ones back to spaces
  $text = preg_replace("/([^;])&nbsp;([^&])/", "$1 $2", $text);

  // Once more to get the remaining &nbsp; after single chars
  $text = preg_replace("/([^;])&nbsp;([^&])/", "$1 $2", $text);
}

function searchBody($match) {
  global $i;
  return '<a name="' . $i . '" href="#' . ++$i . '"><b>' . $match[0] . '</b></a>';
}

?>
<html>
<head>
<title><?php echo htmlspecialchars($title); ?></title>
</head>
<body>
<?php
if ($file != '') {
?>
<div style="font-family: courier">
<?php echo $text; ?>
</div>
<?php
} else {
  echo "You may view the following files.<br>Click on a file name or click a radio button and click one of the buttons below the list.<p>\n";
  echo "<form action='#1' method='get'>\n";
  foreach ($files as $line) echo $line;
  echo "<p>Search selected file for: <input type='text' name='search'> <input type='submit' name='Go' value='Go'/>\n";
  echo "<br>View selected file with line numbers? <input type='submit' name='numbers' value='Yes'>\n";
  echo "</form>\n";
 }
?>
</body>
</html>

<?php

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
