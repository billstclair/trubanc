<?php

  // fsdb.php - File System Database

require_once "perf.php";

class fsdb {

  var $dir = false;
  var $locks = array();

  function fsdb($dir) {
    $this->dir = $dir;
  }

  function rmkdir($path, $mode=0775) {
    if (is_dir($path)) return true;
    $path = rtrim(preg_replace(array("/\\\\/", "/\/{2,}/"), "/", $path), "/");
    $e = explode("/", ltrim($path, "/"));
    if(substr($path, 0, 1) == "/") {
        $e[0] = "/".$e[0];
    }
    $c = count($e);
    $cp = $e[0];
    for($i = 1; $i < $c; $i++) {
      // kluge for safe-mode. First element in path must already exist
      if (($e[$i-1] != "..") && !@is_dir($cp)) {
        //echo "mkdir($cp, $mode)<br>\n";
        @mkdir($cp, $mode);
      }
      $cp .= "/".$e[$i];
    }
    //echo "final mkdir($path, $mode)<br>\n";
    return @mkdir($path, $mode);
  }

  function normalize_key($key) {
    if ($key[0] == '/') return substr($key, 1);
    return $key;
  }

  function filename(&$key) {
    $key = $this->normalize_key($key);
    $dir = $this->dir;
    return "$dir/$key";
  }

  function put($key, $value) {
    $idx = perf_start('fsdb->put');
    $res = $this->put_internal($key, $value);
    perf_stop($idx);
    return $res;
  }

  function put_internal($key, $value) {
    if ($value === false) $value = '';
    $blank = ($value === '');
    $filename = $this->filename($key);
    $fp = @fopen($filename, $blank ? 'r' : 'w');
    if (!$fp) {
      if ($blank) return '';
      if (!$this->rmkdir(dirname($filename))) {
        if ($blank) return '';
        die("Can't make dir for $filename\n");
      }
      $fp = @fopen($filename, 'w');
      if (!$fp) {
        if ($blank) return '';
        die("Can't open for write: $filename\n");
      }
    }
    if (!@$this->locks[$key]) flock($fp, LOCK_EX);
    if ($blank) {
      @unlink($filename);
      // Should delete the empty directories in the path, too.
    }
    else fwrite($fp, $value);
    fclose($fp);
    return $value;
  }
      
  function get($key) {
    $idx = perf_start('fsdb->get');
    $res = $this->get_internal($key);
    perf_stop($idx);
    return $res;
  }

  function get_internal($key) {
    $filename = $this->filename($key);
    $fp = @fopen($filename, 'r');
    if (!$fp) return false;
    if (!@$this->locks[$key]) flock($fp, LOCK_SH);
    $size = filesize($filename);
    if ($size == 0) $value = '';
    else $value = fread($fp, $size);
    fclose($fp);
    return $value;
  }

  function lock($key, $create=false) {
    $locks = $this->locks;
    $lock = @$locks[$key];
    if ($lock) {
      $lock[2]++;
      return $lock;
    }
    $filename = $this->filename($key);
    $fp = @fopen($filename, 'r');
    $created = false;
    if (!$fp) {
      if ($create) {
        if ($this->rmkdir(dirname($filename))) @touch($filename);
        $created = true;
        $fp = @fopen($filename, 'r');
      }
      if (!$fp) return false;
    }
    flock($fp, LOCK_EX);
    $lock = array($fp, $key, 1, $created ? $filename : false);
    $this->locks[$key] = $lock;
    return $lock;
  }

  function unlock($lock) {
    if ($lock) {
      if (--$lock[2] <= 0) {
        $filename = $lock[3];
        if ($filename && file_exists($filename) && @filesize($filename) == 0) {
          @unlink($filename);
        }
        fclose($lock[0]);
        // Windows won't let you delete an open file
        if ($filename && file_exists($filename) && @filesize($filename) == 0) {
          @unlink($filename);
        }
        unset($this->locks[$lock[1]]);
      }
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
