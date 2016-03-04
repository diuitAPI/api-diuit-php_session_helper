<?php
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload

use Diuit\DiuitTokenHelper;

class sessionTokenTest extends PHPUnit_Framework_TestCase
{
	public function testSessionCreation()
	{
		
$pvrKey ='-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAgZJrA5FpyCkEjRKNx2TrGolhWK8tAoxxeCSbu9IUTQ2gVOhvV+x2/CC8
Z7Hcaov+03wVVf41LIpHlAMA51C/Z+EekAjmAu6sEbkjLUQhswt3j0NuAdwDEYUqOu4kBgqi
zSlGv12lsH2oIO38qxmmRZD24omP4JCc+jT9noMqm3Ct6U+YTCAOQ7PA/Oss4crzLAsJrLJM
npJI3j0LN2iBHfGPbM6v5lXoab2LiR13KMcWxSkytljfl7QvGN4RtWDwyd1CeT0X9dxkDEKe
rVjdj4DeUOWK9PQFCU5m83yL5jPBPQ69D6bmiN9+TtFiI6uqvVu6i+gIl0t7Jgoaau4ZFwID
AQABAoIBADqAd1zXDOHY0zs2w1jh0dzbZl56SWI7MwhBzybQRWY83sU3ZP5Xv6k6xpYzEgfx
SY8HGUMIUc3YaVUEviWyqZknZXs26VMtm/cslhtcBbMnXEYM9eBVC/WfIGAXIaCwsKzdFBpX
F/ZF5eFoUoqWPCJwv2etII8N/DJkNpaZNmWTob8Yl9DEIBDzHP6giIoHr2K6v47Q6JApLV+g
EhtSMhYYKyHWtGrbTBPfWc8gdBGlbX5VUEg5d6rliv0uRISD6tVg585i/6PGiez8Iphz+bKe
lzw6yWBzRDjwBdhyC5Mb24An8X/wb05c6vi2VkXfvnlCsNIIbpLl/9+Auu5i+8ECgYEA8E9Q
W1izTcdhwyIkx8bmKLyh2uWzgC/59KGY2hkrd0w0HgASW3Ug6H0MCfGO39vR7hWhBpD2Z9AC
pgE9olJRG1A+jiTomrvCcThcXNVsQ35ON/afO3c9kQBadhOXjpTqtvp4e5b/cdwJYmgjPlBP
LLcjlSscMu7WrCpnqdXjCocCgYEAiggpx1RkYySnAKAWOLe1zOxbD5ViFuDQuVl5JNr+7Nnw
guae02Yv+UUiey+LqAyYJQlqLkc/wjt5xLre+KVhi4KerUaedbpeNkeNmXqRnt9PdfdIfn41
fLO7mFkACL6ysBN1PoxPoax4l1y6bxesiJrplstAav1tU69f1hKhUPECgYBFHmr8exzHiEuE
NrPhikH1AZyEO4FPo3z/ceNnB8pKu+5ZmqetCpl2hVELIyF3HeDZ2/q+yr80yM2aNc0mfQq7
Em+Lru4AY3Tf39ghE3naR9/zlMnj7r4UkMd0Itp6tjZ0fsJcueerNiC030MTz0GWmO5xHz8z
HyM7zc6XON/ezQKBgFqT7MaPDKk6nhR8+NgTRcvJth/NyWZ19MIMgsC6rNrEUV209LiIsCaF
RZFMq/qE+TokqXbg7mgJG2kLr9G+xPoFpxbR5p4exEAeSD9U/UYiCETDFuFa9MJ2Nz5L+QfE
DAIbYq6+6GqRgTjicrz/7gpejbaUfhs3Xoyx4tPZud4hAoGARcA3xHFdyi94LXRJBqe04ZdY
BZ9e1s9fffAnJgST2ZGFJhtx31ugKvWLvMzcW+nGaq02Fn6YjZvIni/rScDVT8hvvEPZbDkQ
mSTqy3gN4rJAVWIDCFxdysD5PmK6d7yhT3iKbiynVbX/C23K9TEIUs+YUj2LwmU0AmV4/Ix1
CCc=
-----END RSA PRIVATE KEY-----';
		$pvrKeyPath = 'file:///Users/diuitPo/Code/diuit/diuit-session-token-helper/tests/privateKey.pem';

		$appId = '97cb20312922117c9f0704fa2a56e5d8';
		$appKey = "79cb79f07a7494ac0dc989177fc87ecc";
		$keyID = "6282f6f5b5a02e6dca54220c99c1d5d6";
		$userSerial = "user.id.6";
		$deviceId = 'device.id.7';
		$platform = 'ios_sandbox';
		$pushToken = 'pushTokenLa';
		$session = (new DiuitTokenHelper())->setAppId($appId)
		                                 ->setAppKey($appKey)
		                                 ->setUserSerial($userSerial)
		                                 ->setKeyID($keyID)
		                                 ->setPrivateKey($pvrKeyPath)
		                                 ->setExpDuration(7*24*3600)
		                                 ->getSessionToken($deviceId, $platform, $pushToken);
		$this->assertNotEquals($session, '', 'session token should not be null');
	}
}
