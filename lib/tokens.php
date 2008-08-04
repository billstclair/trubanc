<?PHP

  // tokens.php
  // tokenize the protocol strings

class tokens {

  // db file & directory names
  var $TIME = 'time';
  var $PRIVKEY = 'privkey';
  var $BANKID = 'bankid';
  var $TOKENID = 'tokenid';
  var $REGFEE = 'regfee';
  var $TRANFEE = 'tranfee';
  var $FEE = 'fee';
  var $PUBKEY = 'pubkey';
  var $PUBKEYSIG = 'pubkeysig';
  var $ASSET = 'asset';
  var $ACCOUNT = 'account';
  var $LAST = 'last';
  var $REQ = 'req';
  var $BALANCE = 'balance';
  var $MAIN = 'main';
  var $OUTBOX = 'outbox';
  var $OUTBOXHASH = 'outboxhash';
  var $INBOX = 'inbox';

  // request names
  var $ID = 'id';
  var $REGISTER = 'register';
  var $FAILED = 'failed';
  var $REASON = 'reason';
  var $GETREQ = 'getreq';
  var $GETFEES = 'getfees';
  var $SPEND = 'spend';
  var $PROCESSINBOX = 'processinbox';
  var $SPENDACCEPT = 'spend|accept';
  var $SPENDREJECT = 'spend|reject';
  var $AFFIRM = 'affirm';
  var $GETASSET = 'getasset';
  var $GETOUTBOX = 'getoutbox';
  var $GETBALANCE = 'getbalance';

  // Affirmations
  var $ATREGISTER = '@register';
  var $ATOUTBOXHASH = '@outboxhash';
  var $ATBALANCE = '@balance';
  var $ATSPEND = '@spend';
  var $ATASSET = '@asset';
  var $ATINBOX = '@inbox';
  var $ATPROCESSINBOX = '@processinbox';

  // request parameter names
  var $CUSTOMER = 'customer';
  var $NAME = 'name';
  var $NOTE = 'note';
  var $ACCT = 'acct';
  var $OPERATION = 'operation';
  var $TRAN = 'tran';
  var $AMOUNT = 'amount';
  var $ASSETNAME = 'assetname';
  var $SCALE = 'scale';
  var $PRECISION = 'precision';
  var $HASH = 'hash';
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
