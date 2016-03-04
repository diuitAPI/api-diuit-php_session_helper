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
		$headers = array("x-diuit-application-id: " . $this->_appId, "x-diuit-app-key: " . $this->_appKey, 'Content-type: application/x-www-form-urlencoded');
		// get nonce
		$nonceUrl = 'https://api.diuit.net/1/auth/nonce';
		$nonceOp = array(
		    'http' => array(
		        'header'  => $headers,
		        'method'  => 'GET',
		    ),
		);
		$nonceContx  = stream_context_create($nonceOp);
		$result = fopen($nonceUrl, 'r', false, $nonceContx);
		$nonceData = stream_get_contents($result);
		fclose($result);
		$nonceObj = json_decode($nonceData);
		$nonce = $nonceObj->nonce;
		echo "nonce:" . $nonce;
		// generate JWT
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
								->setIssuer($this->_appId) // Configures the issuer
								->setSubject($this->_userSerial)
		                        ->set("iat", $iat)
		                        ->set("exp", $exp)
		                        ->set("nonce", $nonce)
		                        ->sign($signer, $pvKey)
		                        ->getToken(); // Retrieves the generated token
		$jwt = substr($token, 0); //JWT.toString

		// retrieve session token
		$url = 'https://api.diuit.net/1/auth/login';
		$data = array('jwt' => $jwt, 'deviceId' => $deviceId, 'platform' => $platform);
		if ($pushToken) {
			$data['pushToken'] = $pushToken;
		}
		$postOp = array(
		    'http' => array(
		        'header'  => $headers,
		        'method'  => 'POST',
		        'content' => http_build_query($data),
		    ),
		);
		$postContext  = stream_context_create($postOp);
		$postResult = fopen($url, 'r', false, $postContext);
		$returnData = stream_get_contents($postResult);
		fclose($postResult);
		$sessionJson = json_decode($returnData);
		$sessionToken = $sessionJson->session;
		echo "\nsession:" . $sessionToken;
		return $sessionToken;
	}
}
?>