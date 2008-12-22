<?php

  // An ever-incremeasing timestamp that stays pretty close to the actual time

class timestamp {

  var $lasttime = 0;

  function timestamp($lasttime=0) {
    $this->lasttime = $lasttime;
  }

  // Get the next timestamp.
  // This is the unix timestamp if > the last result.
  // Otherwise, we add some fractions to make it bigger.
  function next($lasttime=false) {
    if ($lasttime === false) $lasttime = $this->lasttime;
    $time = time();
    if (bccomp($time, $lasttime) <= 0) {
      $pos = strpos($lasttime, '.');
      $n = 2;
      $inc = 1;
      if ($pos === false) {
        $zeros = str_repeat('0', $n-1);
        $time = "$lasttime.$zeros" . '1';
      } else {
        $fract = substr($lasttime, $pos+1);
        $fractlen = strlen($fract);
        $nfract = bcadd($fract, 1);
        if (strlen($nfract) <= $fractlen) {
          $zeros = str_repeat('0', $fractlen - strlen($nfract));
          $time = substr($lasttime, 0, $pos) . '.' . $zeros . $nfract;
        } else {
          $l = $n;
          while (true) {
            if ($l > $fractlen) {
              $zeros = str_repeat('0', $l - $fractlen - 1);
              $time = $lasttime . $zeros . '1';
              break;
            }
            $n += $inc;
            $l += $n;
          }
        }
      }
    }
    $this->lasttime = $time;
    return $time;
  }

  // return the integer part of a time returned by next() above
  function stripfract($time) {
    $dotpos = strpos($time, '.');
    if ($dotpos) $time = substr($time, 0, $dotpos);
    return $time;
  }

}

/*
// Test code
$timestamp = new timestamp();
$time = $timestamp->next();
for ($i=0; $i<100; $i++) $time2 = $timestamp->next();
for ($i=0; $i<1000; $i++) $time3 = $timestamp->next();
for ($i=0; $i<10000; $i++) $time4 = $timestamp->next();
$stripped = $timestamp->stripfract($time4);

echo "time: $time, time2: $time2, time3: $time3, time4: $time4\n";
echo "stripped: $stripped\n";
*/
?>
