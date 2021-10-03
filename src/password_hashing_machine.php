<?php
namespace Yarri;

class PasswordHashingMachine {

	protected $algorithms = [];

	function addAlgorithm($hash_callback,$is_hash_callback = null,$check_password_callback = null){
		if(is_null($is_hash_callback)){
			$hash = $hash_callback("check");
			if(preg_match("/^[0-9a-f]+$/",$hash)){
				$length = strlen($hash);
				$pattern = "/^[0-9a-f]{".$length."}$/";
				$is_hash_callback = function($password) use($pattern) {
					return preg_match($pattern,$password);
				};
			}
		}
		if(is_null($is_hash_callback)){
			throw new InvalidArgumentException('PasswordHashingMachine::addAlgorithm(): Missing 2nd parameter $is_hash_callback');
		}

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
		if(!$this->algorithms){
			throw new PasswordHashingMachine\NoAlgorithmException();
		}
		$callback = $this->algorithms[0]["hash_callback"];
		$hash = $callback($password);
		if(strlen($hash)==0){
			throw new PasswordHashingMachine\HashingFailedException();
		}
		return $hash;
	}

	function isHash($password){
		if(!$this->algorithms){
			throw new PasswordHashingMachine\NoAlgorithmException();
		}
		foreach($this->algorithms as $algo){
			$is_hash_callback = $algo["is_hash_callback"];
		 	if($is_hash_callback($password)){
				return true;
			}
		}
		return false;
	}
	
	function checkPassword($password,$hash,&$is_legacy_hash = null){
		$password = (string)$password;
		$hash = (string)$hash;
		$is_legacy_hash = null;

		if(!$this->algorithms){
			throw new PasswordHashingMachine\NoAlgorithmException();
		}

		foreach($this->algorithms as $i => $algo){
			$is_hash_callback = $algo["is_hash_callback"];
			$check_password_callback = $algo["check_password_callback"];
			if(!$is_hash_callback($hash)){ continue; }
			if($check_password_callback($password,$hash)){
				$is_legacy_hash = $i>0;
				return true;
			}
		}

		return false;
	}

  function verify($password,$hash,&$is_legacy_hash = null){
    return $this->checkPassword($password,$hash,$is_legacy_hash);
  }
}
