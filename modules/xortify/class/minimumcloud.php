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
 * This File:	minimumcloud.php		
 * Description:	API Calls for JSON minimumcloud Routines in Xortify Cloud
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

foreach (get_loaded_extensions() as $ext){
	if ($ext=="curl")
		$nativecurl=true;
}

if ($nativecurl==true) {
	if (!defined('XOOPS_MINIMUMCLOUD_LIB'))
		define('XOOPS_MINIMUMCLOUD_LIB', 'PHPCURL');
	if (!defined('XORTIFY_USER_AGENT'))
		define('XORTIFY_USER_AGENT', sprintf(_MI_XOR_USER_AGENT, _MI_XOR_NAME, _MI_XOR_VERSION, _MI_XOR_RUNTIME, _MI_XOR_MODE));
}
if (!defined('XOOPS_MINIMUMCLOUD_LIB'))
	define('XOOPS_MINIMUMCLOUD_LIB', 'PHPWGET');

if (!defined('XORTIFY_REST_API'))
	define('XORTIFY_REST_API', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urirest'].'%s/json/?%s');

include_once(XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php');

class MinimumcloudXortifyExchange {

	var $curl_client;
	var $minimumcloud_xoops_username = '';
	var $minimumcloud_xoops_password = '';
	var $refresh = 600;
		
	function __construct()
	{
		$this->MinimumcloudXortifyExchange ();
	}
	
	function MinimumcloudXortifyExchange ($url) {
		////error_reporting(0);
		
		$module_handler =& xoops_gethandler('module');
		$config_handler =& xoops_gethandler('config');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->mid());
		
		$this->minimumcloud_xoops_username = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_username'];
		$this->minimumcloud_xoops_password = md5($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_password']);
		$this->refresh = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_records'];

		if (XOOPS_MINIMUMCLOUD_LIB=='PHPCURL') {
			if (!$ch = curl_init($url)) {
				trigger_error('Could not intialise minimumcloud file: '.XORTIFY_REST_API);
				return false;
			}
			$cookies = XOOPS_VAR_PATH.'/cache/xoops_cache/authminimumcloud_'.md5(XORTIFY_REST_API).'.cookie'; 
	
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_connecttimeout']);
			curl_setopt($ch, CURLOPT_TIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_timeout']);
			curl_setopt($ch, CURLOPT_COOKIEJAR, $cookies); 
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
			curl_setopt($ch, CURLOPT_USERAGENT, XORTIFY_USER_AGENT); 
			$this->curl_client =& $ch;
		}			
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
		return isset($result)?$result:array();
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
		return isset($result)?$result:array();
	}
	
	function checkForSpam($content, $adult=false) {
		if (checkWordLength($content)==false&&is_group(user_groups(), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['check_spams'])==true)
			return array('spam'=>true);
		if (is_group(user_groups(), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['check_spams'])==false)
			return array('spam'=>false);
		xoops_load('XoopsUserUtility');
		try {
			$header = "Content-type: text/html; charset=utf-8";		
			$header .= "\nMIME-version: 1.0";
			$header .= "\nContent-transfer-encoding: quoted-printable";
			$header .= "\nSubject: ".$_SERVER['REQUEST_URI'];
			$header .= "\nFrom: ".(is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('uname'):'guest')."@".$_SERVER['REMOTE_ADDR'];
			$header .= "\nTo: ".(is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('uname'):'guest')."@".$_SERVER['HTTP_HOST'];
			$header .= "\nDate: ".date('D, d M Y H:i:s +1000');
			$header .= "\n\n";		
	
			$exe = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_spamc'] . ' -c --retry-sleep=2 ';
			if ($scores!=false) {
				$exe .= '-r ';
			}
			exec($exe . '< ' . $header . $content, $report, $code);
			$result = array('spam' => (intval($code)==0?false:true));
			if ($scores!=false) {
				$result['report'] = $report;
			}
		}
		catch (Exception $e) { trigger_error($e); }
		return isset($result)?$result:array();
	
	}
	
	function getServers() {
		return array();	
	}

	function sendBan($comment, $category_id = 2, $ip=false) {
		$ipData = xortify_getIPData($ip);
		if (XOOPS_MINIMUMCLOUD_LIB=='PHPCURL') {
			try {
				curl_setopt($this->curl_client, CURLOPT_URL, sprintf(XORTIFY_REST_API, 'ban', http_build_query(array(      "username"	=> 	$this->minimumcloud_xoops_username, 
								"password"	=> 	$this->minimumcloud_xoops_password, 
								"bans" 		=> 	array(	0 	=> 	array_merge(
																			$ipData, 
																			array('category_id' => $category_id)
																			)
												),
								"comments" 	=> 	array(	0	=>	array(	'uname'		=>		$this->minimumcloud_xoops_username, 
																		"comment" 	=> 		$comment
																)
												 ) ))));
				$data = curl_exec($this->curl_client);
				curl_close($this->curl_client);
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }		
		} else {
			try {
				$data = file_get_contents(sprintf(XORTIFY_REST_API, 'ban', http_build_query( array(      "username"	=> 	$this->minimumcloud_xoops_username,
						"password"	=> 	$this->minimumcloud_xoops_password,
						"bans" 		=> 	array(	0 	=> 	array_merge(
								$ipData,
								array('category_id' => $category_id)
						)
						),
						"comments" 	=> 	array(	0	=>	array(	'uname'		=>		$this->minimumcloud_xoops_username,
								"comment" 	=> 		$comment
						)
						)
				))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
		}
		return isset($result)?$result:array();	
	}

	private function checksfsbans_GetFromToHost($data) {
		if (XOOPS_MINIMUMCLOUD_LIB=='PHPCURL') {
			try {
				if (!$ch = curl_init($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_sfs_api'].'?'.$data)) {
					trigger_error('Could not intialise CURL file: '.$url);
					return false;
				}
				$cookies = XOOPS_VAR_PATH.'/cache/xoops_cache/authcurl_'.md5($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_sfs_api']).'.cookie';
				curl_setopt($ch, CURLOPT_HEADER, 0);
				curl_setopt($ch, CURLOPT_POST, 0);
				curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
				curl_setopt($ch, CURLOPT_COOKIEJAR, $cookies);
				curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
				curl_setopt($ch, CURLOPT_USERAGENT, XORTIFY_USER_AGENT);
				curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_connecttimeout']);
				curl_setopt($ch, CURLOPT_TIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_timeout']);
				$data = curl_exec($ch);
				curl_close($ch);
			}
			catch (Exception $e) { trigger_error($e); }
		} else {
			try {
				$data = file_get_contents($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_sfs_api'].'?'.$data);
			}
			catch (Exception $e) { trigger_error($e); }
		}
		return xortify_obj2array(json_decode($data));
	}
	
	function checkSFSBans($ipdata) {
		try {
			$result = $this->checksfsbans_GetFromToHost('f=json&username='.$ipdata['uname'].'&email='.$ipdata['email'].'&ip='.$ipdata['ip4'].$ipdata['ip6'].'&api_key='.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_sfs_key']);
		}		
		catch (Exception $e) { trigger_error($e); }
		return isset($result)?$result:array();	
	}

	private function checkphpbans_dolookup($apikey,$ip){
		$itman = $apikey . "." . $ip . "." . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_php_api'];
		$host = gethostbyname($itman);
		return ($host);
	}
	
	function checkPHPBans($ipdata) {
		$octet = array();
		try {
			$what2lookup = implode('.', array_reverse(explode('.',$ipdata['ip4'])));
			$octet = implode('.', checkphpbans_dolookup($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['xortify_mc_php_key'], $what2lookup));
		}
		catch (Exception $e) { trigger_error($e); }		
		return array('success'	=>	($octet[0]=='127')?true:false,
					 'octeta'	=>	$octet[1],
					 'octetb'	=>	$octet[2],
					 'octetc'	=>	$octet[3]);	
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
		if (XOOPS_MINIMUMCLOUD_LIB=='PHPCURL') {
			try {
				curl_setopt($this->curl_client, CURLOPT_URL, sprintf(XORTIFY_REST_API, 'bans', http_build_query(array("username"=> $this->minimumcloud_xoops_username, "password"=> $this->minimumcloud_xoops_password,  "records"=> $this->refresh)	 ) ));
				$data = curl_exec($this->curl_client);
				curl_close($this->curl_client);				
				$result = xortify_obj2array(json_decode($data));
			}		
			catch (Exception $e) { trigger_error($e); }
		} else {
			try {
				$data = file_get_contents(sprintf(XORTIFY_REST_API, 'bans', http_build_query(array("username"=> $this->minimumcloud_xoops_username, "password"=> $this->minimumcloud_xoops_password,  "records"=> $this->refresh))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
		}
		return isset($result)?$result:array();
	}

	function checkBanned($ipdata) {
		if (XOOPS_MINIMUMCLOUD_LIB=='PHPCURL') {
			try {
				curl_setopt($this->curl_client, CURLOPT_URL, sprintf(XORTIFY_REST_API, 'banned', http_build_query(array("username"=> $this->minimumcloud_xoops_username, "password"=> $this->minimumcloud_xoops_password,  "ipdata"=> $ipdata)	 ) ));
				$data = curl_exec($this->curl_client);
				curl_close($this->curl_client);				
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }				
		} else {
			try {
				$data = file_get_contents(sprintf(XORTIFY_REST_API, 'banned', http_build_query(array("username"=> $this->minimumcloud_xoops_username, "password"=> $this->minimumcloud_xoops_password,  "ipdata"=> $ipdata))));
				$result = xortify_obj2array(json_decode($data));
			}
			catch (Exception $e) { trigger_error($e); }
		}		
		return isset($result)?$result:array();
	}
	
	
}

?>