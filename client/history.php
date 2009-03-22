<?php

  // History display and update for Trubanc client

class history {

  // Get or set the history count
  function historycount($newcount=false) {
    global $client;

    $key = 'history/count';
    if ($newcount == false) {
      $newcount = $client->userpreference($key);
      if ($newcount === '') $newcount = 30;
    } else $client->userpreference('history/count', $newcount);
    return $newcount;
  }

  function draw_history($start=1, $count=false) {
    global $body;
    global $error;
    global $client;

    $t = $client->t;

    if ($count === false) $count = $this->historycount();

    $times = $client->gethistorytimes();
    if (is_string($times)) $error = $times;
    elseif (count($times) == 0) $error = "No saved history";
    else {
      settitle('History');
      setmenu('balance');

      // Need controls for pagination, and date search.
      // Eventually, recipient, note, and amount search, too. 
      $cnt = count($times);
      $count2 = ($count <= 0) ? $cnt : $count;
      if ($count2 >= $cnt) $start = 1;
      $strt = $start - 1;
      $end = $strt + $count2;
      if ($end > $cnt) $end = $cnt;
      $idx = 0;
      $body = "<br/>\n";
      $this->scroller($start, $count, $cnt);
      $body .= <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="dohistory"/>
<input type="hidden" name="start" value="$start"/>
<input type="hidden" name="count" value="$count"/>
<input type="hidden" name="chkcnt" value="$cnt"/>
<table border="1">
<caption><b>=== History ===</b></caption>
<tr>
<th>Time</th>
<th>Request</th>
<th>From</th>
<th>To</th>
<th colspan="2">Amount</th>
<th>Note</th>
<th>Response</th>
<th>x</th>
</tr>

EOT;
      $nickcnt = 0;
      for ($i=$strt; $i<$end; $i++) {
        $time = $times[$i];
        $items = $client->gethistoryitems($time);
        if (is_string($items)) {
          $error = $items;
          break;
        }
        $datestr = datestr($time);
        $timestr = hsc($time);
        $datestr = "<span title=\"$timestr\">$datestr</span>";
        $body .= <<<EOT
<tr>

EOT;
        // There are currently three types of history items:
        // 1) Spend
        // 2) Process Inbox
        //   a) Accept or reject of somebody else's spend
        //   b) Acknowledgement of somebody else's accept or reject of my spend
        $item = $items[0];
        $request = $item[$t->REQUEST];
        if ($request == $t->SPEND) {
          $req = 'spend';
          $from = 'You';
          $toid = $item[$t->ID];
          $to = id_namestr($toid, $contact);
          if (!@$contact[$t->CONTACT] && $toid != $client->id && $toid != 'coupon') {
            $to .= <<<EOT
<br/>
<input type="hidden" name="nickid$nickcnt" value="$toid"/>
Nickname:
<input type="text" name="nick$nickcnt" size="10"/>
EOT;
            $nickcnt++;
          }
          $amount = $item[$t->FORMATTEDAMOUNT];
          $assetname = $item[$t->ASSETNAME];
          $note = @$item[$t->NOTE];
          if (!$note) $note = '&nbsp;';
          $body .= <<<EOT
<td>$datestr</td>
<td>$req</td>
<td>$from</td>
<td>$to</td>
<td align="right" style="border-right-width: 0;">$amount</td>
<td style="border-left-width: 0;">$assetname</td>
<td>$note</td>
<td>&nbsp;</td>
<td>
<input type="hidden" name="time$idx" value="$timestr"/>
<input type="checkbox" name="chk$idx"/>
</td>

EOT;
        } elseif ($request == $t->PROCESSINBOX) {
          $rows = array();
          $req = false;
          for ($j=1; $j<count($items); $j++) {
            for (;$j<count($items); $j++) {
              $item = $items[$j];
              $request = $item[$t->REQUEST];
              if ($request == $t->SPENDACCEPT || $request == $t->SPENDREJECT) {
                if ($req) break;
                $req = ($request == $t->SPENDACCEPT) ? 'accept' : 'reject';
                $cancelp = ($item[$t->CUSTOMER] == $client->id);
                $response = $item[$t->NOTE];
                $toid = $item[$t->CUSTOMER];
                $to = id_namestr($toid, $contact, 'You');
                if (!@$contact[$t->CONTACT] && $toid != $client->id && $toid != 'coupon') {
                  $to .= <<<EOT
<br/>
<input type="hidden" name="nickid$nickcnt" value="$toid"/>
Nickname:
<input type="text" name="nick$nickcnt" size="10"/>
EOT;
                  $nickcnt++;
                }
              } elseif ($request == $t->SPEND) {
                $fromid = $item[$t->CUSTOMER];
                $from = id_namestr($fromid, $contact, 'You');
                if (!@$contact[$t->CONTACT] && $fromid != $client->id && $toid != 'coupon') {
                  $from .= <<<EOT
<br/>
<input type="hidden" name="nickid$nickcnt" value="$fromid"/>
Nickname:
<input type="text" name="nick$nickcnt" size="10"/>
EOT;
                  $nickcnt++;
                }
                $toid = $item[$t->ID];
                if ($to) {
                  // $to set above by spendaccept/spendredeem code
                  if ($toid == 'coupon') {
                    $to = "Coupon redeemed by:<br/>$to";
                  }
                } else {
                  $to = id_namestr($toid, $contact, 'You');
                  if (!$contact[$t->CONTACT] && $toid != $client->id && $toid != 'coupon') {
                    $to .= <<<EOT
<br/>
<input type="hidden" name="nickid$nickcnt" value="$toid"/>
Nickname:
<input type="text" name="nick$nickcnt" size="10"/>
EOT;
                    $nickcnt++;
                  }
                }
                $amount = $item[$t->FORMATTEDAMOUNT];
                $assetname = $item[$t->ASSETNAME];
                $note = @$item[$t->NOTE];
                if ($item[$t->ATREQUEST] == $t->ATSPEND) {
                  $req = $cancelp ? "=$req" : "@$req";
                }
              }
            }
            if ($req) {
              $row = array('req' => $req,
                           'from' => $from,
                           'to' => $to,
                           'amount' => $amount,
                           'assetname' => $assetname,
                           'note' => $note,
                           'response' => $response);
              $rows[] = $row;
              if ($j > 1) $j--;
              $req = false;
              $from = false;
              $to = false;
              $amount = false;
              $assetname = false;
              $note = false;
              $response = false;
            }
          }
          $rowcnt = count($rows);
          if ($rowcnt > 0) {
            $body .= "<td rowspan=\"$rowcnt\">$datestr</td>\n";
            $first = true;
            foreach ($rows as $row) {
              if (!$first) $body .= "<tr>\n";
              $req = $row['req'];
              $from = $row['from'];
              $to = $row['to'];
              $amount = $row['amount'];
              $assetname = $row['assetname'];
              $note = $row['note'];
              $response = $row['response'];
              $checkcode = '';
              if ($first) {
                $checkcode = <<<EOT

<td rowspan="$rowcnt">
<input type="hidden" name="time$idx" value="$timestr"/>
<input type="checkbox" name="chk$idx"/>
</td>
EOT;
                $first = false;
              }
              if (!$note) $note = '&nbsp;';
              if (!$response) $response = '&nbsp;';
              $body .= <<<EOT
<td>$req</td>
<td>$from</td>
<td>$to</td>
<td align="right" style="border-right-width: 0;">$amount</td>
<td style="border-left-width: 0;">$assetname</td>
<td>$note</td>
<td>$response</td>$checkcode
</tr>

EOT;
            }
          }
        } else {
          $req = hsc($req);
          $body .= <<<EOT
<td>$datestr</td>
<td>$req</td>
<td colspan="6">Unknown request type</td>

EOT;
        }
        $body .= "</tr>\n";
        $idx++;
      }
      if ($nickcnt > 0) {
        $body .= <<<EOT
<input type="hidden" name="nickcnt" value="$nickcnt"/>

EOT;
        $submitlabel = "Delete Checked & Add Nicknames";
      } else {
        $submitlabel = "Delete Checked";
      }
      $body .= <<<EOT
</table>
<br/>
<input type="submit" name="delete" value="$submitlabel"/>
<input type="submit" name="deleteolder" value="Delete Checked & Older"/>
</form>

EOT;
      $this->scroller($start, $count, $cnt);
      if (hideinstructions()) {
        $body .= <<<EOT
<a href="./?cmd=toggleinstructions&page=history">Show Instructions</a>

EOT;
      } else {
        $body .= <<<EOT
<table border="1">
<caption><b>=== Key ===</b></caption>
<tr><td>spend</td><td>You made a spend</td></tr>
<tr><td>accept</td><td>You accepted a spend</td></tr>
<tr><td>reject</td><td>You rejected a spend</td></tr>
<tr><td>@accept</td><td>You acknowledged acceptance of your spend</td></tr>
<tr><td>@reject</td><td>You acknowledged rejection of your spend</td></tr>
<tr><td>=reject</td><td>You acknowledged your cancel of a spend</td></tr>
<tr><td>=accept</td><td>You acknowledged your acceptance of a coupon you spent to yourself</td></tr>
</table>
<br/>
<a href="./?cmd=toggleinstructions&page=history">Hide Instructions</a>

EOT;
      }
    }
    if ($error) draw_balance();
  }

  function scroller($start, $count, $cnt) {
    global $body;

    if (strtolower($count) == 'all') $count = 0;
    $count2 = ($count <= 0) ? $cnt : $count;

    if ($count <= 0) $count = 'ALL';
    $count = hsc($count);
    $start = hsc($start);
    $cnt = hsc($cnt);

    $body .= <<<EOT
<form method="post" action="./" autocomplete="off">
<input type="hidden" name="cmd" value="dohistory">
<input type="hidden" name="cnt" value="$cnt"/>

EOT;
    $disabled = '';
    if ($start <= 1) $disabled = ' disabled="disabled"';
    $body .= <<<EOT
<input type="submit" name="top" value="&lt;&lt;"$disabled title="Show the first page"/>
<input type="submit" name="pageup" value="&lt;"$disabled title="Show the previous page"/>

EOT;

    $body .= <<<EOT
Start:
<input type="text" name="start" size="6" value="$start"/>
<input type="submit" name="show" value="Show:"/>
<input type="text" name="count" size="4" value="$count"/>
of $cnt entries

EOT;

    $disabled = '';
    if (($start + $count2) > $cnt) $disabled = ' disabled="disabled"';
    $body .= <<<EOT
<input type="submit" name="pagedown" value="&gt;"$disabled title="Show the next page"/>
<input type="submit" name="bottom" value="&gt;&gt;"$disabled title="Show the last page"/>

EOT;

    $body .= "</form>\n";
  }

  function do_history() {
    global $client;

    // Delete or set nickname values
    $delete = mqpost('delete');
    $deleteolder = mqpost('deleteolder');

    $chkcnt = mqpost('chkcnt');
    $nickcnt = mqpost('nickcnt');

    // Scroller values
    $top = mqpost('top');
    $pageup = mqpost('pageup');
    $show = mqpost('show');
    $pagedown = mqpost('pagedown');
    $bottom = mqpost('bottom');

    $start = mqpost('start');
    $count = mqpost('count');
    $cnt = mqpost('cnt');

    if ($delete || $deleteolder) {
      for ($i=0; $i<$nickcnt; $i++) {
        $nick = mqpost("nick$i");
        if ($nick) {
          $id = mqpost("nickid$i");
          $client->addcontact($id, $nick);
        }
      }

      for ($i=0; $i<$chkcnt; $i++) {
        $chk = mqpost("chk$i");
        if ($chk) {
          $deltime = mqpost("time$i");
          if ($delete) {
            $client->removehistoryitem($deltime);
          } elseif ($deleteolder) {
            $times = $client->gethistorytimes();
            foreach ($times as $time) {
              if (bccomp($deltime, $time) >= 0) {
                $found = true;
                $client->removehistoryitem($time);
              }
            }
            break;
          }
        }
      }
    } else {
      if ($top) $start = 1;
      elseif ($pageup) $start -= $count;
      elseif ($pagedown) $start += $count;
      elseif ($bottom) $start = $cnt - $count + 1;

      if ($start < 1) $start = 1;
      elseif ($start > $cnt) {
        $start = $cnt - ($cnt % $count) + 1;
        if ($start > $cnt) $start = $cnt - $count + 1;
        if ($start < 1) $start = 1;
      }

      $this->historycount($count);
    }

    $this->draw_history($start, $count);
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
