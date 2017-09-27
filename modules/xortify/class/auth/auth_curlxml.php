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
 * This File:	auth_curl.php		
 * Description:	Auth Library with CURL XML routines for signup and API
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */
 
if (!defined('XORTIFY_CURLXML_API'))
	define('XORTIFY_CURLXML_API', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urixml']);

if (!defined('XORTIFY_USER_AGENT'))
		define('XORTIFY_USER_AGENT', sprintf(_MI_XOR_USER_AGENT, _MI_XOR_NAME, _MI_XOR_VERSION, _MI_XOR_RUNTIME, _MI_XOR_MODE));
	
include_once XOOPS_ROOT_PATH . '/modules/xortify/class/auth/auth_curlxml_provisionning.php';

class XortifyAuthCurlxml extends XortifyAuth {
	
	var $curl_client;
	var $curl_xoops_username = '';
	var $curl_xoops_password = '';
	var $_dao;
	var $_json = '';
	/**
	 * Authentication Service constructor
	 */
	function XortifyAuthCurlxml (&$dao) {
		if (!$ch = curl_init(XORTIFY_CURLXML_API)) {
			trigger_error('Could not intialise CURL file: '.$url);
			return false;
		}
		$cookies = XOOPS_VAR_PATH.'/cache/xoops_cache/authcurl_'.md5(XORTIFY_CURLXML_API).'.cookie'; 

		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_connecttimeout']);
		curl_setopt($ch, CURLOPT_TIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['curl_timeout']);
		curl_setopt($ch, CURLOPT_COOKIEJAR, $cookies); 
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); 
		curl_setopt($ch, CURLOPT_VERBOSE, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_USERAGENT, XORTIFY_USER_AGENT); 
		$this->curl_client =& $ch;
	}


	/**
	 *  Authenticate  user again curl directory (Bind)
	 *
	 * @param string $uname Username
	 * @param string $pwd Password
	 *
	 * @return bool
	 */	
	function authenticate($uname, $pwd = null) {
		$authenticated = false;
		$this->XortifyAuthCurlxml($GLOBALS['xoopsDB']);
		
		if (!$this->curl_client) {
			$this->setErrors(0, _AUTH_CURL_EXTENSION_NOT_LOAD);
			return $authenticated;
		}

				
		$rnd = rand(-100000, 100000000);
		curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'xoops_authentication='. xortify_toXml(array("username"=> $this->curl_xoops_username, "password"=> $this->curl_xoops_password, "auth" => array('username' => $uname, "password" => $pwd, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pwd), "rand"=>$rnd)), 'xoops_authentication'));
		$data = curl_exec($this->curl_client);
		curl_close($this->curl_client);
		$result = xortify_elekey2numeric(xortify_xml2array($data), 'xoops_authentication');
		return $result['xoops_authentication']["RESULT"];		
	}
	
				  
	/**
	 *  validate a user via curl
	 *
	 * @param string $uname
	 * @param string $email
	 * @param string $pass
	 * @param string $vpass
	 *
	 * @return string
	 */		
	function validate($uname, $email, $pass, $vpass){
		$this->XortifyAuthCurlxml($GLOBALS['xoopsDB']);
		$rnd = rand(-100000, 100000000);
		curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'xoops_user_validate=' . xortify_toXml(array("username"=> $this->curl_xoops_username, "password"=> $this->curl_xoops_password, "validate" => array('uname' => $uname, "pass" => $pass, "vpass" => $vpass, "email" => $email, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd)), 'xoops_user_validate'));
		$data = curl_exec($this->curl_client);
		curl_close($this->curl_client);
		$result = xortify_elekey2numeric(xortify_xml2array($data), 'xoops_user_validate');
		if ($result['xoops_user_validate']['ERRNUM']==1){
			return $result['xoops_user_validate']["RESULT"];
		} else {
			return false;
		}
	
	}

	
	/**
	 *  get the xoops site disclaimer via curl
	 *
	 * @return string
	 */			
	function network_disclaimer(){
		$this->XortifyAuthCurlxml($GLOBALS['xoopsDB']);
		curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'xoops_network_disclaimer=' . xortify_toXml(array("username"=> $this->curl_xoops_username, "password"=> $this->curl_xoops_password), 'xoops_network_disclaimer'));
		$data = curl_exec($this->curl_client);
		curl_close($this->curl_client);
		$result = xortify_elekey2numeric(xortify_xml2array($data), 'xoops_network_disclaimer');
		if ($result['xoops_network_disclaimer']['ERRNUM']==1){
			return $result['xoops_network_disclaimer']["RESULT"];
		} else {
			return false;
		}

	}
	
	/**
	 *  create a user
	 *
	 * @param bool $user_viewemail
	 * @param string $uname
	 * @param string $email
	 * @param string $url
	 * @param string $actkey
	 * @param string $pass
	 * @param integer $timezone_offset
	 * @param bool $user_mailok		 
	 * @param array $siteinfo
	 *
	 * @return array
	 */	
	function create_user($user_viewemail, $uname, $email, $url, $actkey, 
						 $pass, $timezone_offset, $user_mailok, $siteinfo){
						 
		$siteinfo = $this->check_siteinfo($siteinfo);

		$rnd = rand(-100000, 100000000);
		$this->XortifyAuthCurlxml($GLOBALS['xoopsDB']);
		curl_setopt($this->curl_client, CURLOPT_POSTFIELDS, 'xoops_create_user='.xortify_toXml(array("username"=> $this->curl_xoops_username, "password"=> $this->curl_xoops_password, "user" => array('user_viewemail' =>$user_viewemail, 'uname' => $uname, 'email' => $email, 'url' => $url, 'actkey' => $actkey, 'pass' => $pass, 'timezone_offset' => $timezone_offset, 'user_mailok' => $user_mailok, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd), "siteinfo" => $siteinfo), 'xoops_create_user'));
		$data = curl_exec($this->curl_client);
		curl_close($this->curl_client);	
		$result = xortify_elekey2numeric(xortify_xml2array($data), 'xoops_create_user');	
		if ($result['xoops_create_user']['ERRNUM']==1){
			return $result['xoops_create_user']["RESULT"];		
		} else {
			return false;
		}
	}
	
		
}
// end class


?>
