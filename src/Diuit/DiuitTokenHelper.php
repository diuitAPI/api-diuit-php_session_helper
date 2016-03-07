<?php

namespace Diuit;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;

/**
 * This class makes easier the session token creation process of DiuitMessaging
 *
 * @author   Pofat Tseng <pofattseng@diuit.com>
 */

class DiuitTokenHelper
{
	private $_appId;
	private $_appKey;
	private $_userSerial;
	private $_keyID;
	private $_privateKey;
	private $_expDuration;

	/**
     * Initializes a new DiuitSessionTokenHelper
     *
     */
	public function __construct()
	{
		// JWT requires timezeone to be set
		if (!ini_get('date.timezone')) {
		    date_default_timezone_set('GMT');
		}
	}

	/**
     * Configures appId
     *
     * @param string $appId
     *
     * @return diuitTokenHelper
     */
	public function setAppId($appId)
	{
		$this->_appId = $appId;
		return $this;
	}

	/**
     * Configures appKey
     *
     * @param string $appKey
     *
     * @return diuitTokenHelper
     */
	public function setAppKey($appKey)
	{
		$this->_appKey = $appKey;
		return $this;
	}

	/**
     * Configures user serial
     *
     * @param string $userSerial
     *
     * @return diuitTokenHelper
     */
	public function setUserSerial($userSerial)
	{
		$this->_userSerial = $userSerial;
		return $this;
	}

	/**
     * Configures key id (for finding public key)
     *
     * @param string $keyID
     *
     * @return diuitTokenHelper
     */
	public function setKeyID($keyID)
	{
		$this->_keyID = $keyID;
		return $this;
	}

	/**
     * Configures private key
     *
     * @param string $privateKey
     *
     * @return diuitTokenHelper
     */
	public function setPrivateKey($privateKey)
	{
		$this->_privateKey = $privateKey;
		return $this;
	}

	/**
     * Configures valid duration (in second)
     *
     * @param int $duration
     *
     * @return diuitTokenHelper
     */
	public function setExpDuration($duration)
	{
		$this->_expDuration = $duration;
		return $this;
	}

	/**
     * Get session token, $deviceId and $platform are required
     *
     * @param string $deviceId
     * @param string $platform ('gcm', 'ios_sandbox', or 'ios_production')
     * @param string $pushToken
     *
     * @return JSON
     * {
     *     "session": $SESSION_TOKEN,
     *     "userId": $USER_SERIAL,
     *     "deviceId": $DEVICE_SERIAL
     * }
     *
     */
	public function getSessionToken($deviceId, $platform, $pushToken = null)
	{
		$headers = array("x-diuit-application-id: " . $this->_appId, "x-diuit-app-key: " . $this->_appKey, 'Content-type: application/json');
		// get nonce
		$nonceJson = $this->doGET('https://api.diuit.net/1/auth/nonce', $headers);
		$nonce = $nonceJson->nonce;
		echo "nonce:" . $nonce;
		// generate JWT
		$jwt = $this->generateAuthJWT($nonce);
		// retrieve session token
		$data = array('jwt' => substr($jwt, 0), 'deviceId' => $deviceId, 'platform' => $platform);
		if ($pushToken) {
			$data['pushToken'] = $pushToken;
		}

		$sessionJSON = $this->doPOST('https://api.diuit.net/1/auth/login', $headers, $data);
		$sessionToken = $sessionJSON->session;
		echo "\nsession:" . $sessionToken;
		return $sessionToken;
	}

	/**
		 * Generate JWT string
		 *
		 * @param string $nonce
		 *
		 * @return Token
		 *
		 */
	public function generateAuthJWT($nonce)
	{
		$signer = new Sha256();
		$pvKey = new Key($this->_privateKey);
		$now = gmdate("Y-m-d H:i:s", time());
		$expDate = gmdate("Y-m-d H:i:s", time() + $this->_expDuration);
		$dt = new \DateTime($now);
		$expdt = new \DateTime($expDate);
		$iat = $dt->format(\DateTime::ISO8601);
		$exp = $expdt->format(\DateTime::ISO8601);
		$token = (new Builder())->setHeader('alg','RS256')
								->setHeader('cty','diuit-auth;v=1')
								->setHeader('kid',$this->_keyID)
								->setIssuer($this->_appId)
								->setSubject($this->_userSerial)
		                        ->set("iat", $iat)
		                        ->set("exp", $exp)
		                        ->set("nonce", $nonce)
		                        ->sign($signer, $pvKey)
		                        ->getToken(); // Retrieves the generated token
		return $token;
	}

	/**
     * do GET request
     *
     * @param string $url
     * @param array $headers
     *
     * @return JSON
     *
     */
	private function doGET($url, $headers)
	{
		$options = array(
		    'http' => array(
		        'header'  => $headers,
		        'method'  => 'GET',
		    ),
		);
		$context  = stream_context_create($options);
		$result = fopen($url, 'r', false, $context);
		$contents = stream_get_contents($result);
		fclose($result);
		return json_decode($contents);
	}
	/**
     * do POST request
     *
     * @param string $url
     * @param array $headers
		 * @param array $obdy
     *
     * @return JSON
     *
     */
	private function doPOST($url, $headers, $body)
	{
		$options = array(
		    'http' => array(
		        'header'  => $headers,
		        'method'  => 'POST',
		        'content' => json_encode($body),
		    ),
		);
		$context  = stream_context_create($options);
		$result = fopen($url, 'r', false, $context);
		$contents = stream_get_contents($result);
		fclose($result);
		return json_decode($contents);
	}
}
?>
