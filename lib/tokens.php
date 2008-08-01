<?PHP

  // tokens.php
  // tokenize the protocol strings

class tokens {

  // db file & directory names
  var $SEQUENCE = 'sequence';
  var $PRIVKEY = 'privkey';
  var $BANKID = 'bankid';
  var $REGFEE = 'regfee';
  var $REGFEESIG = 'regfeesig';
  var $TRANFEE = 'tranfee';
  var $TRANFEESIG = 'tranfeesig';
  var $FEE = 'fee';
  var $FEESIG = 'feesig';
  var $PUBKEY = 'pubkey';
  var $PUBKEYSIG = 'pubkeysig';
  var $ASSET = 'asset';
  var $ASSETNAME = 'assetname';
  var $ACCOUNT = 'account';
  var $LAST = 'last';
  var $LASTREQUEST = 'lastrequest';
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
  var $GETLASTREQUEST = 'getlastrequest';
  var $GETFEES = 'getfees';
  var $SPEND = 'spend';
  var $PROCESSINBOX = 'processinbox';
  var $NOTE = 'note';
  var $ACCT = 'acct';
  var $SPENDACCEPT = 'spend|accept';
  var $SPENDREJECT = 'spend|reject';
  var $AFFIRM = 'affirm';
  var $GETASSET = 'getasset';
  var $GETOUTBOX = 'getoutbox';
  var $GETBALANCE = 'getbalance';

  // request parameter names
  var $CUSTOMER = 'customer';
  var $REQ = 'req';
  var $NAME = 'name';
  var $RANDOM = 'random';
  var $REQUEST = 'request';
  var $OPERATION = 'operation';
  var $TRAN = 'tran';
  var $AMOUNT = 'amount';
  var $TRANLIST = 'tranlist';
  var $SCALE = 'scale';
  var $PRECISION = 'precision';
}

?>
