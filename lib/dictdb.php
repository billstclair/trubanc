<?php

  // dictdb.php
  // Simple array-based dictionary

class dictdb {

  var $dict = array();

  function get($key) {
    return $this->dict[$key];
  }

  function put($key, $value) {
    $this->dict[$key] = $value;
    return $value;
  }

}