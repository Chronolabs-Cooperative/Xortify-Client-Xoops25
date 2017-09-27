<?php
/*
 * Prevents Spam, Harvesting, Human Rights Abuse, Captcha Abuse etc.
 * basic statistic of them in XOOPS Copyright (C) 2012 Simon Roberts 
 * Contact: wishcraft - simon@chronolabs.com.au
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * See /docs/license.pdf for full license.
 * 
 * Shouts:- 	Mamba (www.xoops.org), flipse (www.nlxoops.nl)
 * 				Many thanks for your additional work with version 1.01
 * 
 * Version:		4.99.1 Final (Stable)
 * Published:	Chronolabs
 * Download:	http://sourceforge.net/projects/xortify
 * This File:	curlserialised.php		
 * Description:	CURL API Routines for Serialisation Packages
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

foreach (get_loaded_extensions() as $ext){
	if ($ext=="curl")
		$nativecurl=true;
}

if ($nativecurl==true) {
	if (!defined('XOOPS_CURLSERIAL_LIB'))
		define('XOOPS_CURLSERIAL_LIB', 'PHPCURLSERIAL');
		
	if (!defined('XORTIFY_USER_AGENT'))
			define('XORTIFY_USER_AGENT', sprintf(_MI_XOR_USER_AGENT, _MI_XOR_NAME, _MI_XOR_VERSION, _MI_XOR_RUNTIME, _MI_XOR_MODE));
		
}

if (!defined('XORTIFY_CURLSERIAL_API'))
	define('XORTIFY_CURLSERIAL_API', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_uriserial']);

include_once(XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php');

class CURLSERIALISEDXortifyExchange {

	var $curl_client;
	var $serial_xoops_username = '';
	var $serial_xoops_password = '';
	var $refresh = 600;
	var $json = '';
	
	function __construct()
	{
		$this->CURLSERIALISEDXortifyExchange ();
	}
	
	function CURLSERIALISEDXortifyExchange () {
		////error_reporting(0);
		
		$module_handler =& xoops_gethandler('module');
		$config_handler =& xoops_gethandler('config');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->mid());
		
		$this->serial_xoops_username = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_username'];
		$this->serial_xoops_password = md5($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_password']);
		$this->refresh = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_records'];

		if (!$this->curl_client = curl_init(XORTIFY_CURLSERIAL_API)) {
			trigger_error('Could not intialise CURLSERIAL file: '.XORTIFY_CURLSERIAL_API);
			return false;
		}
		$cookies = XOOPS_VAR_PATH.'/cache/xoops_cache/authcurl_'.md5(XORTIFY_CURLSERIAL_API).'.cookie'; 

		curl_setopt($this->curl_client, CURLOPT_HEADER, 0);
		curl_setopt($this->curl_client, CURLOPT_POST, 1);
		curl_setopt($this->curl_client, CURLOPT_CONNECTTIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_connecttimeout']);
		curl_setopt($this->curl_client, CURLOPT_TIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_timeout']);
		curl_setopt($this->curl_client, CURLOPT_COOKIEJAR, $cookies); 
		curl_setopt($this->curl_client, CURLOPT_RETURNTRANSFER, true); 
		curl_setopt($this->curl_client, CURLOPT_VERBOSE, false);
		curl_setopt($this->curl_client, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($this->curl_client, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($this->curl_client, CURLOPT_USERAGENT, XORTIFY_USER_AGENT); 
	
	}

/*
	 * Provides training document to API
	 * 
	 * @param string $content
	 * @param boolean $ham
	 * @return boolean
	 */
	 function training($content, $ham = false) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
				case "PHPCURLSERIAL":
					try {
						curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
						curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'training=' . serialize(array("username"	=> 	$this->serial_xoops_username,
							"password"	=> 	$this->serial_xoops_password,
							'op' => ($ham==true?'ham':'spam'),
							'content' => $content
						)));
						$data = curl_exec($this->curl_client);
						curl_close($this->curl_client);
						$result = unserialize($data);
					}
					catch (Exception $e) { trigger_error($e); }
					break;
		}
		return isset($result)?$result:array();
	}
	
	/*
	 * Checks is content is spam
	 * 
	 * @param string $content
	 * @return boolean
	 */
	 function checkForSpam($content) {
		if (checkWordLength($content)==false&&is_group(user_groups(), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['check_spams'])==true)
			return array('spam'=>true);
		if (is_group(user_groups(), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['check_spams'])==false)
			return array('spam'=>false);
	 	xoops_load('XoopsUserUtility');
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'spamcheck='.serialize(array(      "username"	=> 	$this->serial_xoops_username,
					"password"	=> 	$this->serial_xoops_password, "poll" => XOOPS_URL.'/modules/xortify/poll/',
					'content' => $content,
					'uname' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('uname'):''),
					'name' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('name'):''),
					'email' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('email'):''),
					'ip' => (class_exists('XoopsUserUtility')?XoopsUserUtility::getIP(true):$_SERVER['REMOTE_ADDR']),
					'session' => session_id()
					)));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = unserialize($data);
				}
				catch (Exception $e) { trigger_error($e); }
				break;
		}
		return isset($result)?$result:array();
	
	}

	/*
	 * Get a Spoof/Trick form from the cloud
	 * 
	 * @param string $type
	 * @return array
	 */
	 function getSpoof($type = 'comment') {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
					try {
						xoops_load('XoopsUserUtility');
						$uu = new XoopsUserUtility();
						curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
						curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, "spoof$type=" . serialize(array(      "username"	=> 	$this->serial_xoops_username,
						"password"	=> 	$this->serial_xoops_password, "uri" => (isset($_SERVER['HTTPS'])?'https://':'http://').$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
						'ip' => $uu->getIP(true),
						'language' => $GLOBALS['xoopsConfig']['language'],
						'subject' => ''
								)));
								$data = curl_exec($this->curl_client);
								curl_close($this->curl_client);
								$result = (unserialize($data));
					}
					catch (Exception $e) { trigger_error($e); }
					break;
			}
		return isset($result)?$result:array();
	}
	
	function getServers() {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'servers='.serialize(array(      "username"	=> 	$this->serial_xoops_username, 
									"password"	=> 	$this->serial_xoops_password, "poll" => XOOPS_URL.'/modules/xortify/poll/', 
									'token' => $GLOBALS['xoopsSecurity']->createToken(3600, 'poll_token'),
									'agent' => $_SERVER['HTTP_USER_AGENT'],
									'session' => session_id()
								)));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = (unserialize($data));
				}
				catch (Exception $e) { trigger_error($e); }				
				break;
			}
		return isset($result)?$result:array();	
	}
	

	function sendBan($comment, $category_id = 2, $ip=false) {
		$ipData = xortify_getIPData($ip);
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'ban='.serialize(array(      "username"	=> 	$this->serial_xoops_username, 
									"password"	=> 	$this->serial_xoops_password, 
									"bans" 		=> 	array(	0 	=> 	array_merge(
																				$ipData, 
																				array('category_id' => $category_id)
																				)
													),
									"comments" 	=> 	array(	0	=>	array(	'uname'		=>		$this->serial_xoops_username, 
																			"comment" 	=> 		$comment
																	)
													 ) )));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = (unserialize($data));
				}
				catch (Exception $e) { trigger_error($e); }				
				break;
			}
		return isset($result)?$result:array();	
	}

	function checkSFSBans($ipdata) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'checksfsbans='.serialize(array(      "username"	=> 	$this->serial_xoops_username, 
									"password"	=> 	$this->serial_xoops_password, 
									"ipdata" 	=> 	$ipdata
								)));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = (unserialize($data));
				}
				catch (Exception $e) { trigger_error($e); }				
				break;
			}
		return isset($result)?$result:array();	
	}

	function checkPHPBans($ipdata) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'checkphpbans='.serialize(array(      "username"	=> 	$this->serial_xoops_username, 
									"password"	=> 	$this->serial_xoops_password, 
									"ipdata" 	=> 	$ipdata
								)));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = (unserialize($data));
				}
				catch (Exception $e) { trigger_error($e); }		
				break;
			}
		return isset($result)?$result:array();	
	}
	
	function getBans() {
		xoops_load('xoopscache');
		if (!class_exists('XoopsCache')) {
			// XOOPS 2.4 Compliance
			xoops_load('cache');
			if (!class_exists('XoopsCache')) {
				include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
			}
		}
        if (! $bans = @$GLOBALS['xoopsCache']->read('xortify_bans_cache')) {
				$bans = @$GLOBALS['xoopsCache']->read('xortify_bans_cache_backup');
				$GLOBALS['xoDoSoap'] = true;
        }
		return $bans;
	}	
	
	function retrieveBans() {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'bans='.serialize(array("username"=> $this->serial_xoops_username, "password"=> $this->serial_xoops_password,  "records"=> $this->refresh)	 ) );
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);				
					$result = (unserialize($data));
				}
				catch (Exception $e) { trigger_error($e); }		
			}
		return isset($result)?$result:array();
	}

	function checkBanned($ipdata) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLSERIAL_LIB){
			case "PHPCURLSERIAL":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'banned='.serialize(array("username"=> $this->serial_xoops_username, "password"=> $this->serial_xoops_password,  "ipdata"=> $ipdata)	 ) );
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);				
					$result = (unserialize($data));
				}
				catch (Exception $e) { trigger_error($e); }				
			break;
		}		
		return isset($result)?$result:array();
	}
	
}

?>