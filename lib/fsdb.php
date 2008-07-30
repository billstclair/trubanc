<?php

  // fsdb.php - File System Database

class fsdb {

  var $dir = false;

  function fsdb($dir) {
    $this->dir = $dir;
  }

  function rmkdir($path, $mode = 0755) {
    $path = rtrim(preg_replace(array("/\\\\/", "/\/{2,}/"), "/", $path), "/");
    $e = explode("/", ltrim($path, "/"));
    if(substr($path, 0, 1) == "/") {
        $e[0] = "/".$e[0];
    }
    $c = count($e);
    $cp = $e[0];
    for($i = 1; $i < $c; $i++) {
        if(!is_dir($cp) && !@mkdir($cp, $mode)) {
            return false;
        }
        $cp .= "/".$e[$i];
    }
    return @mkdir($path, $mode);
  }

  function normalize_key ($key) {
    if ($key[0] == '/') return substr($key, 1);
    return $key;
  }

  function put($key, $value) {
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    $filename = "$dir/$key";
    $fp = @fopen($filename, 'w');
    if (!$fp) {
      if (!$this->rmkdir(dirname($filename))) return false;
      $fp = fopen($filename, 'w');
      if (!$fp) return false;
    }
    flock($fp, LOCK_EX);
    fwrite($fp, $value);
    fclose($fp);
    return $value;
  }
      
  function get($key) {
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    $filename = "$dir/$key";
    $fp = @fopen($filename, 'r');
    if (!$fp) return false;
    flock($fp, LOCK_SH);
    $value = fread($fp, filesize($filename));
    fclose($fp);
    return $value;
  }

  function lock($key) {
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    $filename = "$dir/$key";
    $fp = @fopen($filename, 'r');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    return $fp;
  }

  function unlock($fp) {
    fclose($fp);
  }
}

// Testing code
/*
$value = $argv[$argc-1];
$db = new fsdb("./db");
if ($db->put("/foo/bar", $value)) {
  echo $db->get("/foo/bar") . "\n";
}
$fp = $db->lock("/foo/bar");
if ($fp) {
  echo "Type something:";
  fgets(STDIN);
  $db->unlock($fp);
}
else echo "Couldn't get lock";
*/
?>
