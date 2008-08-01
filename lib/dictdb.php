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
