<?php
class curl {

  var $headers;
  var $user_agent;
  var $compression;
  var $cookie_file;
  var $proxy;                   // "$ip:$port"
  var $process;
  var $trycurl = true;

  function curl($cookies=FALSE,$cookie='cookies.txt',$compression='gzip',$proxy='') {
    //$this->headers[] = 'Accept: image/gif, image/x-bitmap, image/jpeg, image/pjpeg';
    $this->headers[] = 'Keep-Alive: 300';
    $this->headers[] = 'Connection: keep-alive';
    $this->headers[] = 'Content-type: application/x-www-form-urlencoded';
    $this->user_agent = 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.0.7) Gecko/2009021906 Firefox/3.0.7';
    $this->compression=$compression;
    $this->proxy=$proxy;
    $this->cookies=$cookies;
    if ($this->cookies == TRUE) $this->cookie($cookie);
  }

  function cookie($cookie_file) {
    if (file_exists($cookie_file)) {
      $this->cookie_file=$cookie_file;
    } else {
      if (!fopen($cookie_file,'w')) {
        $this->error('The cookie file could not be opened. Make sure this directory has the correct permissions');
      }
      $this->cookie_file=$cookie_file;
      fclose($this->cookie_file);
    }
  }

  function getprocess($url=null) {
    if (!$this->trycurl) return null;
    $process = $this->process;
    if (!$process) {
      $process = @curl_init();
      if (!$process) {
        $this->trycurl = false;
        return null;
      }
      $this->process = $process;
    }
    if ($url) curl_setopt($process, CURLOPT_URL, $url);
    return $process;
  }

  function get($url) {
    $process = $this->getprocess($url);
    if (!$process) return file_get_contents($url);
    curl_setopt($process, CURLOPT_HTTPHEADER, $this->headers);
    curl_setopt($process, CURLOPT_HEADER, 0);
    curl_setopt($process, CURLOPT_USERAGENT, $this->user_agent);
    if ($this->cookies == TRUE) curl_setopt($process, CURLOPT_COOKIEFILE, $this->cookie_file);
    if ($this->cookies == TRUE) curl_setopt($process, CURLOPT_COOKIEJAR, $this->cookie_file);
    curl_setopt($process,CURLOPT_ENCODING , $this->compression);
    curl_setopt($process, CURLOPT_TIMEOUT, 30);
    if ($this->proxy) curl_setopt($process, CURLOPT_PROXY, $this->proxy);
    curl_setopt($process, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($process, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($process, CURLOPT_HTTPGET, 1);
    $return = curl_exec($process);
    return $return;
  }

  function post($url, $data=array()) {
    $process = $this->getprocess($url);
    if (!$process) return $this->post_simple($url, $data);
    curl_setopt($process, CURLOPT_HTTPHEADER, $this->headers);
    curl_setopt($process, CURLOPT_HEADER, 0);
    curl_setopt($process, CURLOPT_USERAGENT, $this->user_agent);
    if ($this->cookies == TRUE) curl_setopt($process, CURLOPT_COOKIEFILE, $this->cookie_file);
    if ($this->cookies == TRUE) curl_setopt($process, CURLOPT_COOKIEJAR, $this->cookie_file);
    curl_setopt($process, CURLOPT_ENCODING , $this->compression);
    curl_setopt($process, CURLOPT_TIMEOUT, 30);
    if ($this->proxy) curl_setopt($process, CURLOPT_PROXY, $this->proxy);
    curl_setopt($process, CURLOPT_POST, 1);
    curl_setopt($process, CURLOPT_POSTFIELDS, http_build_query($data));
    curl_setopt($process, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($process, CURLOPT_FOLLOWLOCATION, 1);
    $return = curl_exec($process);
    return $return;
  }

  function post_simple($url, $post_variables=array()) {
    $content = http_build_query($post_variables);
    $content_length = strlen($content);
    $options = array
      ('http'=>array('method' => 'POST',
                     'header' =>
                     "User-Agent: Trubanc\r\n" .
                     "Content-type: application/x-www-form-urlencoded\r\n" . 
                     "Content-length: $content_length\r\n",
                     'content' => $content));
    $context = stream_context_create($options);
    return @file_get_contents($url, false, $context);
  }

  function close() {
    $process = $this->process;
    $this->process = false;
    if ($process) curl_close($process);
  }

  function error($error) {
    echo "<center><div style='width:500px;border: 3px solid #FFEEFF; padding: 3px; background-color: #FFDDFF;font-family: verdana; font-size: 10px'><b>cURL Error</b><br>$error</div></center>";
    die;
  }
  }

/*
$cc = new curl();
$url = "http://trubanc.com/";
$cc->get($url);
$text = $cc->get($url);
$data = array('foo'=>'bar', 'bar'=>'bletch','bletch'=>'gronk');
$text = $cc->post($url, $data);
echo $text;
$cc->close();
*/
