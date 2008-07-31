<?php

  // fsdb.php - File System Database

class fsdb {

  var $dir = false;
  var $locks = array();

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
    if (value === false) $value = '';
    $blank = ($value === '');
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    $filename = "$dir/$key";
    $fp = @fopen($filename, $blank ? 'r' : 'w');
    if (!$fp) {
      if ($blank) return '';
      if (!$this->rmkdir(dirname($filename))) return false;
      $fp = fopen($filename, 'w');
      if (!$fp) return $blank ? '' : false;
    }
    if (!$this->locks[$key]) flock($fp, LOCK_EX);
    if ($blank) {
      unlink($filename);
      // Should delete the empty directories in the path, too.
    }
    else fwrite($fp, $value);
    fclose($fp);
    return $value;
  }
      
  function get($key) {
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    $filename = "$dir/$key";
    $fp = @fopen($filename, 'r');
    if (!$fp) return false;
    if (!$this->locks[$key]) flock($fp, LOCK_SH);
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
    $this->locks[$key] = true;
    return array($fp, $key);
  }

  function unlock($lock) {
    if ($lock) {
      fclose($lock[0]);
      unset($this->locks[$lock[1]]);
    }
  }

  // Return an array of the names of the contents of the directory,
  // sorted alphabetically.
  // File names beginning with "." are ignored.
  function contents($key) {
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    $dirs = @scandir("$dir/$key");
    $res = array();
    if ($dirs) {
      foreach ($dirs as $dir) {
        if (substr($dir, 0, 1) != ".") $res[] = $dir;
      }
    }
    return $res;
  }

  function subdir($key) {
    $key = $this->normalize_key($key);
    return new fsdb($this->dir . '/' . $key);
  }
}

// Testing code
/*
$value = $argv[$argc-1];
$db = new fsdb("./db");
if ($db->put("/foo/bar", $value)) {
  echo $db->get("/foo/bar") . "\n";
}
if ($db->put("/foo/delete-me", "you'll never see this")) {
  $db->put("foo/delete-me", '');
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
