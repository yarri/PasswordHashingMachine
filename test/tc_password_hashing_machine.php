<?php
class TcPasswordHashingMachine extends TcBase {

	function test(){
		// default algorithm - blowfish privided by MyBlowfish
		$phm = new PasswordHashingMachine(
			function($password){ return MyBlowfish::GetHash($password); },
			function($password){ return MyBlowfish::IsHash($password); },
			function($password,$hash){ return MyBlowfish::CheckPassword($password,$hash); }
		);

		// md5
		$phm->addAlgorithm(
			function($password){ return md5($password); },
			function($password){ return preg_match('/^[0-9a-f]{32}$/',$password); }
		);

		// md5 with salt
		$phm->addAlgorithm(
			function($password){ return md5($password."|site_secret_key"); },
			function($password){ return preg_match('/^[0-9a-f]{32}$/',$password); }
		);

		$blowfish = '$2a$06$rLxnps2CuGC/9BPCq3ms..7uaWETN6GPiVMXYYGWqdQoMZsDQ/kFG'; // hash for secret
		$md5 = 'c8dae1c50e092f3d877192fc555b1dcf'; // hash for sesame
		$md5_salt = 'ad3668c64fb042415863b0b4f9a682b2'; // hash for summer|site_secret_key

		$this->assertEquals("",$phm->filter(""));
		$this->assertEquals(null,$phm->filter(null));

		$p = $phm->filter("alex123");
		$this->assertTrue(strlen($p)>0);
		$this->assertNotEquals("alex123",$p);
		$this->assertTrue(MyBlowfish::IsHash($p));

		$this->assertEquals($blowfish,$phm->filter($blowfish));
		$this->assertEquals($md5,$phm->filter($md5));
		$this->assertEquals($md5_salt,$phm->filter($md5_salt));

		$this->assertTrue($phm->isHash($blowfish));
		$this->assertTrue($phm->isHash($md5));
		$this->assertTrue($phm->isHash($md5_salt));

		$this->assertTrue($phm->checkPassword("secret",$blowfish));
		$this->assertTrue($phm->checkPassword("sesame",$md5));
		$this->assertTrue($phm->checkPassword("summer",$md5_salt));
	}
}
