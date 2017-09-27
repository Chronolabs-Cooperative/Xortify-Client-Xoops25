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
 * This File:	curlxml.php		
 * Description:	CURL XML Routines for XML API Packages
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

foreach (get_loaded_extensions() as $ext){
	if ($ext=="curl")
		$nativecurl=true;
	if ($ext=="SimpleXML")
		$nativexml=true;
		
}

if ($nativecurl==true&&$nativexml==true) {
	define('XOOPS_CURLXML_LIB', 'PHPCURLXML');
	
	if (!defined('XORTIFY_USER_AGENT'))
			define('XORTIFY_USER_AGENT', sprintf(_MI_XOR_USER_AGENT, _MI_XOR_NAME, _MI_XOR_VERSION, _MI_XOR_RUNTIME, _MI_XOR_MODE));
		
}

if (!defined('XORTIFY_CURLXML_API'))
	define('XORTIFY_CURLXML_API', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urixml']);

include_once(XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php');

class CURLXMLXortifyExchange {

	var $curl_client;
	var $xml_xoops_username = '';
	var $xml_xoops_password = '';
	var $refresh = 600;
		
	function __construct()
	{
		$this->CURLXMLXortifyExchange ();
	}
	
	function CURLXMLXortifyExchange () {
		////error_reporting(0);
		
		$module_handler =& xoops_gethandler('module');
		$config_handler =& xoops_gethandler('config');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->mid());
		
		$this->xml_xoops_username = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_username'];
		$this->xml_xoops_password = md5($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_password']);
		$this->refresh = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_records'];

		if (!$this->curl_client = curl_init(XORTIFY_CURLXML_API)) {
			trigger_error('Could not intialise CURL file: '.XORTIFY_CURLXML_API);
			return false;
		}
		$cookies = XOOPS_VAR_PATH.'/cache/xoops_cache/authcurl_'.md5(XORTIFY_CURLXML_API).'.cookie'; 

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
			switch (XOOPS_CURLXML_LIB){
				case "PHPCURLXML":
					try {
						curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
						curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'training=' . xortify_toXml(array("username"	=> 	$this->curl_xoops_username,
							"password"	=> 	$this->curl_xoops_password,
							'op' => ($ham==true?'ham':'spam'),
							'content' => $content
						)));
						$data = curl_exec($this->curl_client);
						curl_close($this->curl_client);
						$result = xortify_elekey2numeric(xortify_xml2array($data), 'training');
					}
					catch (Exception $e) { trigger_error($e); }
					break;
		}
		return $result['training'];
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
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
					try {
						curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
						curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'spamcheck='.xortify_toXml(array(      "username"	=> 	$this->xml_xoops_username,
						"password"	=> 	$this->xml_xoops_password, "poll" => XOOPS_URL.'/modules/xortify/poll/',
						'content' => $content,
						'uname' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('uname'):''),
						'name' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('name'):''),
						'email' => (is_object($GLOBALS['xoopsUser'])?$GLOBALS['xoopsUser']->getVar('email'):''),
						'ip' => (class_exists('XoopsUserUtility')?XoopsUserUtility::getIP(true):$_SERVER['REMOTE_ADDR']),
						'session' => session_id()
						)));
						$data = curl_exec($this->curl_client);
						curl_close($this->curl_client);
						$result = xortify_elekey2numeric(xortify_xml2array($data), 'spamcheck');
					}
					catch (Exception $e) { trigger_error($e); }
					break;
		}
		return $result['spamcheck'];
	
	}


	/*
	 * Get a Spoof/Trick form from the cloud
	 * 
	 * @param string $type
	 * @return array
	 */
	 function getSpoof($type = 'comment') {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
					try {
						xoops_load('XoopsUserUtility');
						$uu = new XoopsUserUtility();
						curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
						curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, "spoof$type=" . xortify_toXml(array(      "username"	=> 	$this->curl_xoops_username,
						"password"	=> 	$this->curl_xoops_password, "uri" => (isset($_SERVER['HTTPS'])?'https://':'http://').$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
						'ip' => $uu->getIP(true),
						'language' => $GLOBALS['xoopsConfig']['language'],
						'subject' => ''
								)));
								$data = curl_exec($this->curl_client);
								curl_close($this->curl_client);
								$result = xortify_elekey2numeric(xortify_xml2array($data), "spoof$type");
					}
					catch (Exception $e) { trigger_error($e); }
					break;
		}
		return $result["spoof$type"];
	}
	
	
	function getServers() {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
				try {
					curl_setopt($this->curl_client, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'servers='.xortify_toXml(array(      "username"	=> 	$this->xml_xoops_username, 
									"password"	=> 	$this->xml_xoops_password, "poll" => XOOPS_URL.'/modules/xortify/poll/', 
									'token' => $GLOBALS['xoopsSecurity']->createToken(3600, 'poll_token'),
									'agent' => $_SERVER['HTTP_USER_AGENT'],
									'session' => session_id()
								), 'servers'));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = xortify_elekey2numeric(xortify_xml2array($data), 'servers');
				}
				catch (Exception $e) { trigger_error($e); }		
				break;
			}
		return $result['servers'];	
	}
	
	function sendBan($comment, $category_id = 2, $ip=false) {
		$ipData = xortify_getIPData($ip);
		if (!empty($this->curl_client))
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'ban='.xortify_toXml(array(      "username"	=> 	$this->xml_xoops_username, 
									"password"	=> 	$this->xml_xoops_password, 
									"bans" 		=> 	array(	0 	=> 	array_merge(
																				$ipData, 
																				array('category_id' => $category_id)
																				)
													),
									"comments" 	=> 	array(	0	=>	array(	'uname'		=>		$this->xml_xoops_username, 
																			"comment" 	=> 		$comment
																	)
													 ) ), 'ban'));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = xortify_elekey2numeric(xortify_xml2array($data), 'ban');
				}
				catch (Exception $e) { trigger_error($e); }		
				break;
			}
		return $result['ban'];	
	}

	function checkSFSBans($ipdata) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'checksfsbans='.xortify_toXml(array(      "username"	=> 	$this->xml_xoops_username, 
									"password"	=> 	$this->xml_xoops_password, 
									"ipdata" 	=> 	$ipdata
								), 'checksfsbans'));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = xortify_elekey2numeric(xortify_xml2array($data), 'checksfsbans');
				}
				catch (Exception $e) { trigger_error($e); }		
				break;
			}
		return $result['checksfsbans'];	
	}

	function checkPHPBans($ipdata) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'checkphpbans='.xortify_toXml(array(      "username"	=> 	$this->xml_xoops_username, 
									"password"	=> 	$this->xml_xoops_password, 
									"ipdata" 	=> 	$ipdata
								), 'checkphpbans'));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);
					$result = xortify_elekey2numeric(xortify_xml2array($data), 'checkphpbans');
				}
				catch (Exception $e) { trigger_error($e); }		
				break;
			}
		return $result['checkphpbans'];	
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
			switch (XOOPS_CURLXML_LIB){
			case "PHPCURLXML":
				try {
					curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'bans='.xortify_toXml(array("username"=> $this->xml_xoops_username, "password"=> $this->xml_xoops_password,  "records"=> $this->refresh), 'bans'));
					$data = curl_exec($this->curl_client);
					curl_close($this->curl_client);				
					$result = xortify_elekey2numeric(xortify_xml2array($data),'bans');
				}
				catch (Exception $e) { trigger_error($e); }		
			}
		return $result['bans'];
	}

	function checkBanned($ipdata) {
		if (!empty($this->curl_client))
			switch (XOOPS_CURLXML_LIB){
				case "PHPCURLXML":
					try {
						curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'banned='.xortify_toXml(array("username"=> $this->xml_xoops_username, "password"=> $this->xml_xoops_password,  "ipdata"=> $ipdata), 'banned'));
						$data = curl_exec($this->curl_client);
						curl_close($this->curl_client);				
						$result = xortify_elekey2numeric(xortify_xml2array($data),'banned');
					}
					
					catch (Exception $e) { trigger_error($e); }				
				break;
			}		
		return isset($result)?$result:array();
	}
	
}

?>