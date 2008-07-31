<?PHP

  // utility.php
  // Utility functions, bundled in a class

class utility {

  // Sort an array of numbers represented as strings.
  // Works even if they're too big to fit in a machine word.
  // Doesn't use bcmath, just prepends leading zeroes.
  // Does NOT clobber the array. Returns a new one.
  function bignum_sort($array) {
    $maxlen = 0;
    foreach ($array as $value) {
      $len = strlen($value);
      if ($len > $maxlen) $maxlen = $len;
    }
    $map = array();
    foreach ($array as $value) {
      $newval = str_repeat('0', $maxlen - strlen($value)) . $value;
      $map[$newval] = $value;
    }
    ksort($map);
    $res = array();
    foreach ($map as $newval => $value) {
      $res[] = $value;
    }
    return $res;
  }

  // Escape a string for inclusion in a message
  function escape($str) {
    $res = '';
    $ptr = 0;
    for ($i=0; $i<strlen($str); $i++) {
      if (!(strpos("(),:.\\", substr($str, $i, 1)) === false)) {
        $res .= substr($str, $ptr, $i - $ptr) . "\\";
        $ptr = $i;
      }
    }
    if ($ptr == 0) return $str;
    $res .= substr($str, $ptr);
    return $res;
  }

  // Make an unsigned message from $array
  function makemsg($array) {
    $msg = "(";
    $i = 0;
    foreach ($array as $key=>$value) {
      if ($i != 0) $msg .= ',';
      if ($key != $i) $msg .= "$key:";
      $msg .= $this->escape($value);
      $i++;
    }
    $msg .= ')';
    return $msg;
  }

}

// Test code
/*
$ut = new utility();
print_r($ut->bignum_sort(array("10","1","20", "2", "99999", "123456")));
*/
?>
