<?php
class PasswordHashingMachine {

	protected $algorithms = [];

	function __construct($hash_callback,$is_hash_callback,$check_password_callback = null){
		return $this->addAlgorithm($hash_callback,$is_hash_callback,$check_password_callback);
	}

	function addAlgorithm($hash_callback,$is_hash_callback,$check_password_callback = null){
		if(is_null($check_password_callback)){
			$check_password_callback = function($password,$hash) use($hash_callback){
				$h = $hash_callback($password);
				return strlen($h)>0 && $h===$hash;
			};
		}
		$this->algorithms[] = [
			"hash_callback" => $hash_callback,
			"is_hash_callback" => $is_hash_callback,
			"check_password_callback" => $check_password_callback,
		];
	}

	function filter($password){
		if(strlen($password)==0){
			return $password;
		}
		
		if($this->isHash($password)){
			return $password;
		}

		return $this->hash($password);
	}

	function hash($password){
		$callback = $this->algorithms[0]["hash_callback"];
		$hash = $callback($password);
		return $hash;
	}

	function isHash($password){
		foreach($this->algorithms as $algo){
			$is_hash_callback = $algo["is_hash_callback"];
		 	if($is_hash_callback($password)){
				return true;
			}
		}
		return false;
	}
	
	function checkPassword($password,$hash){
		$password = (string)$password;
		$hash = (string)$hash;

		foreach($this->algorithms as $algo){
			$is_hash_callback = $algo["is_hash_callback"];
			$check_password_callback = $algo["check_password_callback"];
			if(!$is_hash_callback($hash)){ continue; }
			if($check_password_callback($password,$hash)){
				return true;
			}
		}

		return false;
	}
}
