<?php
require_once __DIR__ . '/../vendor/autoload.php';

use Diuit\DiuitTokenHelper;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key;

class sessionTokenTest extends PHPUnit_Framework_TestCase
{
	public function testSessionCreation()
	{
		$appId = 'testAppId';
		$appKey = "testAppKey";
		$keyID = "testKeyId";
		$userSerial = "testUser";
		$token = (new DiuitTokenHelper())->setAppId($appId)
		                                 ->setAppKey($appKey)
		                                 ->setUserSerial($userSerial)
		                                 ->setKeyID($keyID)
		                                 ->setPrivateKey('file://' . getcwd() .'/tests/privateKey.pem')
		                                 ->setExpDuration(7*24*3600)
																		 ->generateAuthJWT('testNonce');
		//verify token
		$expectIssuer = 'testAppId';
		$expectSubject = 'testUser';
		$newToken = (new Parser())->parse((string) $token); // Parses from a string
		$signer = new Sha256();
		$publicKey = new Key('file://' . getcwd() .'/tests/publicKey.pem');
		if ($newToken->verify($signer, $publicKey)) {
			$this->assertEquals($expectIssuer, $newToken->getClaim('iss'), 'iss did not match expected value');
			$this->assertEquals($expectSubject, $newToken->getClaim('sub'), 'sub did not match expected value');
		} else {
			$this->assertFalse($newToken->verify($signer, $publicKey), 'Public key did not match the private key');
		}
	}
}
