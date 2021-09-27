<?php
namespace Yarri\PasswordHashingMachine;

class NoAlgorithmException extends \Exception {

	function __construct($msg = "No hashing algorithm was specified"){
		return parent::__construct($msg);
	}
}
