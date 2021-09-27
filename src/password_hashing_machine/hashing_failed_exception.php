<?php
namespace PasswordHashingMachine;

class HashingFailedException extends \Exception {

	function __construct($msg = "Hashing failed"){
		return parent::__construct($msg);
	}
}
