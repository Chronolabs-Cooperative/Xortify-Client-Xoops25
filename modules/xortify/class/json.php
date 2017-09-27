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
 * This File:	json.php		
 * Description:	wGET routines for API JSON Packages
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */
 
if (!function_exists('json_encode')){
	function json_encode($data) {
		static $json = NULL;
		if (!class_exists('Services_JSON') ) { include_once $GLOBALS['xoops']->path('/modules/xortify/include/JSON.php'); }
		$json = new Services_JSON();
		return $json->encode($data);
	}
}

if (!function_exists('json_decode')){
	function json_decode($data) {
		static $json = NULL;
		if (!class_exists('Services_JSON') ) { include_once $GLOBALS['xoops']->path('/modules/xortify/include/JSON.php'); }
		$json = new Services_JSON();
		return $json->decode($data);
	}
}


if (!defined('XORTIFY_JSON_API'))
	define('XORTIFY_JSON_API', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urijson']);

include_once(XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php');


define('XOOPS_JSON_LIB', 'PHPJSON');

class JSONXortifyExchange {

	var $json_client;
	var $json_xoops_username = '';
	var $json_xoops_password = '';
	var $refresh = 600;
		
	function __construct()
	{
		$this->JSONXortifyExchange ();
	}
	
	function JSONXortifyExchange () {
		////error_reporting(0);
		
		$module_handler =& xoops_gethandler('module');
		$config_handler =& xoops_gethandler('config');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->mid());
		
		$this->json_xoops_username = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_username'];
		$this->json_xoops_password = md5($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_password']);
		$this->refresh = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_records'];
			
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
			switch (XOOPS_CURLXML_LIB){
				case "PHPCURLXML":
					try {
						$data = file_get_contents(XORTIFY_JSON_API.'?training=' . json_encode(array("username"	=> 	$this->curl_xoops_username,
								"password"	=> 	$this->curl_xoops_password,
								'op' => ($ham==true?'ham':'spam'),
								'content' => $content
						)));
						$result = xortify_obj2array(json_decode($data));
					}
					catch (Exception $e) { trigger_error($e); }
					break;
		}
		return $result;
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
		try {
			$data = file_get_contents(XORTIFY_JSON_API.'?spamcheck='.json_encode(array(      "username"	=> 	$this->json_xoops_username,
					"password"	=> 	$this->json_xoops_password, "poll" => XOOPS_URL.'/modules/xortify/poll/',
					'content' => $content,
					'uname' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('uname'):''),
					'name' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('name'):''),
					'email' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('email'):''),
					'ip' => (class_exists('XoopsUserUtility')?XoopsUserUtility::getIP(true):$_SERVER['REMOTE_ADDR']),
					'session' => session_id()
			)));
			$result = xortify_obj2array(json_decode($data));
		}
		catch (Exception $e) { trigger_error($e); }
		return $result;
	
	}
	
	
	/*
	 * Get a Spoof/Trick form from the cloud
	*
	* @param string $type
	* @return array
	*/
	function getSpoof($type = 'comment') {
		switch (XOOPS_JSON_LIB){
			default:
			case "PHPJSON":
				try {
					xoops_load('XoopsUserUtility');
					$uu = new XoopsUserUtility();
					$data = file_get_contents(XORTIFY_JSON_API."?spoof$type=" . urlencode(json_encode(array(      "username"	=> 	$this->curl_xoops_username,
							"password"	=> 	$this->curl_xoops_password, "uri" => (isset($_SERVER['HTTPS'])?'https://':'http://').$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
							'ip' => $uu->getIP(true),
							'language' => $GLOBALS['xoopsConfig']['language'],
							'subject' => ''
					))));
					$result = xortify_obj2array(json_decode($data));
				}
				catch (Exception $e) { trigger_error($e); }
				break;
		}
		return $result;
	}
	
	
	function getServers() {
		switch (XOOPS_JSON_LIB){
		default:
		case "PHPJSON":
			try {
				$data = file_get_contents(XORTIFY_JSON_API.'?servers='.urlencode(json_encode( array(      "username"	=> 	$this->json_xoops_username, 
								"password"	=> 	$this->json_xoops_password, "poll" => XOOPS_URL.'/modules/xortify/poll/', 
								'token' => $GLOBALS['xoopsSecurity']->createToken(3600, 'poll_token'),
								'agent' => $_SERVER['HTTP_USER_AGENT'],
								'session' => session_id()
						))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
			break;
		}			
		return $result;	
	}
		
	function sendBan($comment, $category_id = 2, $ip=false) {

		$ipData = xortify_getIPData($ip);
		
		switch (XOOPS_JSON_LIB){
		default:
		case "PHPJSON":
			try {
				$data = file_get_contents(XORTIFY_JSON_API.'?ban='.urlencode(json_encode( array(      "username"	=> 	$this->json_xoops_username, 
								"password"	=> 	$this->json_xoops_password, 
								"bans" 		=> 	array(	0 	=> 	array_merge(
																			$ipData, 
																			array('category_id' => $category_id)
																			)
												),
								"comments" 	=> 	array(	0	=>	array(	'uname'		=>		$this->json_xoops_username, 
																		"comment" 	=> 		$comment
																)
												 ) 
						))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
			break;
		}			
		return $result;	
	}

	function checkSFSBans($ipdata) {
		
		switch (XOOPS_JSON_LIB){
		default:
		case "PHPJSON":
			try {
				$data = file_get_contents(XORTIFY_JSON_API.'?checksfsbans='.urlencode(json_encode( 
						array(  "username"	=> 	$this->json_xoops_username, 
								"password"	=> 	$this->json_xoops_password, 
								"ipdata" 	=> 	$ipdata
						))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
			break;
		}			
		return $result;	
	}

	function checkPHPBans($ipdata) {
		
		switch (XOOPS_JSON_LIB){
		default:
		case "PHPJSON":
			try {
				$data = file_get_contents(XORTIFY_JSON_API.'?checkphpbans='.urlencode(json_encode( 
						array(  "username"	=> 	$this->json_xoops_username, 
								"password"	=> 	$this->json_xoops_password, 
								"ipdata" 	=> 	$ipdata
						))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
			break;
		}			
		return $result;	
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
		switch (XOOPS_JSON_LIB){
		default:
		case "PHPJSON":
			try {
				$data = file_get_contents(XORTIFY_JSON_API.'?bans='.urlencode(json_encode(array("username"=> $this->json_xoops_username, "password"=> $this->json_xoops_password,  "records"=> $this->refresh))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
			break;
		}
		return $result;
	}

	function checkBanned($ipdata) {
		switch (XOOPS_JSON_LIB){
		default:
		case "PHPJSON":
			try {
				$data = file_get_contents(XORTIFY_JSON_API.'?banned='.urlencode(json_encode(array("username"=> $this->json_xoops_username, "password"=> $this->json_xoops_password,  "ipdata"=> $ipdata))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
			break;
		}
		return $result;
	}
}


?>