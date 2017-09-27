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
 * This File:	auth_soap.php		
 * Description:	Auth Library with SOAP routines for signup and API
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */
if (!defined('XORTIFY_API_LOCAL'))
	define('XORTIFY_API_LOCAL', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urisoap']);
	
if (!defined('XORTIFY_API_URI'))
	define('XORTIFY_API_URI', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urisoap']);

include_once XOOPS_ROOT_PATH . '/modules/xortify/class/auth/auth_soap_provisionning.php';

if (!file_exists(XOOPS_ROOT_PATH.'/class/soap/xoopssoap.php')){
	foreach (get_loaded_extensions() as $ext){
		if ($ext=="soap")
			$native=true;
	}
	if (!defined('XOOPS_SOAP_LIB'))
		if ($native!=true) {
			define('XOOPS_SOAP_LIB','NUSOAP');
			require_once('../nusoap/nusoap.php');
		} else {
			define('XOOPS_SOAP_LIB','PHPSOAP');
		}
} else {
	require_once (XOOPS_ROOT_PATH.'/class/soap/xoopssoap.php');
}

class XortifyAuthSoap extends XortifyAuth {
	
	var $soap_client;
	var $soap_xoops_username = '';
	var $soap_xoops_password = '';
	var $_dao;
	/**
	 * Authentication Service constructor
	 */
	function XortifyAuthSoap (&$dao) {
		switch (XOOPS_SOAP_LIB){
		case "NUSOAP":
			$this->soap_client = @new soapclient(XORTIFY_API_URI, 'xsoap.wsdl');
			break;
		case "PHPSOAP":
			$this->soap_client = @new soapclient(NULL, array('location' => XORTIFY_API_LOCAL, 'uri' => XORTIFY_API_URI));
			break;
		}
	}


	/**
	 *  Authenticate  user again SOAP directory (Bind)
	 *
	 * @param string $uname Username
	 * @param string $pwd Password
	 *
	 * @return bool
	 */	
	function authenticate($uname, $pwd = null) {
		$authenticated = false;
	
		if (!$this->soap_client) {
			$this->setErrors(0, _AUTH_SOAP_EXTENSION_NOT_LOAD);
			return $authenticated;
		}

				
		$rnd = rand(-100000, 100000000);
		switch (XOOPS_SOAP_LIB){
		case "NUSOAP":
			$result = @$this->soap_client->call('xoops_authentication', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password, "auth" => array('username' => $uname, "password" => $pwd, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pwd), "rand"=>$rnd)));
			break;
		case "PHPSOAP":
			$result = @$this->soap_client->__soapCall('xoops_authentication', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password, "auth" => array('username' => $uname, "password" => $pwd, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pwd), "rand"=>$rnd)));
			break;
		}
		return $result["RESULT"];		
	}
	
				  
	/**
	 *  validate a user via soap
	 *
	 * @param string $uname
	 * @param string $email
	 * @param string $pass
	 * @param string $vpass
	 *
	 * @return string
	 */		
	function validate($uname, $email, $pass, $vpass){
	
		$rnd = rand(-100000, 100000000);
		switch (XOOPS_SOAP_LIB){
		case "NUSOAP":
			$result = @$this->soap_client->call('xoops_user_validate', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password, "validate" => array('uname' => $uname, "pass" => $pass, "vpass" => $vpass, "email" => $email, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd)));
			break;
		case "PHPSOAP":
			$result = @$this->soap_client->__soapCall('xoops_user_validate', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password, "validate" => array('uname' => $uname, "pass" => $pass, "vpass" => $vpass, "email" => $email, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd)));
			break;
		}
		if ($result['ERRNUM']==1){
			return $result["RESULT"];
		} else {
			return false;
		}
	
	}

	/**
	 *  get the xoops site disclaimer via soap
	 *
	 * @return string
	 */			
	function network_disclaimer(){

		switch (XOOPS_SOAP_LIB){
		case "NUSOAP":
			$result = @$this->soap_client->call('xoops_network_disclaimer', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password));
			break;
		case "PHPSOAP":
			$result = @$this->soap_client->__soapCall('xoops_network_disclaimer', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password));
			break;
		}	
		
		if ($result['ERRNUM']==1){
			return $result["RESULT"];
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
		switch (XOOPS_SOAP_LIB){
		case "NUSOAP":
			$result = @$this->soap_client->call('xoops_create_user', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password, "user" => array('user_viewemail' =>$user_viewemail, 'uname' => $uname, 'email' => $email, 'url' => $url, 'actkey' => $actkey, 'pass' => $pass, 'timezone_offset' => $timezone_offset, 'user_mailok' => $user_mailok, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd), "siteinfo" => $siteinfo));
			break;
		case "PHPSOAP":
			$result = @$this->soap_client->__soapCall('xoops_create_user', array("username"=> $this->soap_xoops_username, "password"=> $this->soap_xoops_password, "user" => array('user_viewemail' =>$user_viewemail, 'uname' => $uname, 'email' => $email, 'url' => $url, 'actkey' => $actkey, 'pass' => $pass, 'timezone_offset' => $timezone_offset, 'user_mailok' => $user_mailok, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd), "siteinfo" => $siteinfo));
			break;
		}
		
		if ($result['ERRNUM']==1){

			return $result["RESULT"];
			
		} else {
			return false;
		}
	}
		
}
// end class


?>
