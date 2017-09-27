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
 * This File:	auth_json.php		
 * Description:	Auth Library with wGET JSON routines for signup and API
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

if (!defined('XORTIFY_REST_API'))
	define('XORTIFY_REST_API', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urirest'].'%s/json/?%s');
include_once XOOPS_ROOT_PATH . '/modules/xortify/class/auth/auth_rest_json_provisionning.php';

class XortifyAuthRest_Json extends XortifyAuth {
	
	var $json_client;
	var $json_xoops_username = '';
	var $json_xoops_password = '';
	var $_dao;
	var $_json = '';
	/**
	 * Authentication Service constructor
	 */
	function XortifyAuthRest_Json (&$dao) {

	}


	/**
	 *  Authenticate  user again json directory (Bind)
	 *
	 * @param string $uname Username
	 * @param string $pwd Password
	 *
	 * @return bool
	 */	
	function authenticate($uname, $pwd = null) {
		$authenticated = false;
		$rnd = rand(-100000, 100000000);		
		$data = file_get_contents(sprintf(XORTIFY_REST_API, 'xoops_authentication', http_build_query(array("username"=> $this->json_xoops_username, "password"=> $this->json_xoops_password, "auth" => array('username' => $uname, "password" => $pwd, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pwd), "rand"=>$rnd)))));
			$result = $this->obj2array(json_decode($data));	
		return $result["RESULT"];		
	}
	
				  
	/**
	 *  validate a user via json
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
		$data = file_get_contents(sprintf(XORTIFY_REST_API, 'xoops_user_validate', http_build_query(array("username"=> $this->json_xoops_username, "password"=> $this->json_xoops_password, "validate" => array('uname' => $uname, "pass" => $pass, "vpass" => $vpass, "email" => $email, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd)))));
			$result = $this->obj2array(json_decode($data));	
		if ($result['ERRNUM']==1){
			return $result["RESULT"];
		} else {
			return false;
		}
	
	}

    function reduce_string($str)
    {
        $str = preg_replace(array(

                // eliminate single line comments in '// ...' form
                '#^\s*//(.+)$#m',

                // eliminate multi-line comments in '/* ... */' form, at start of string
                '#^\s*/\*(.+)\*/#Us',

                // eliminate multi-line comments in '/* ... */' form, at end of string
                '#/\*(.+)\*/\s*$#Us'

            ), '', $str);

        // eliminate extraneous space
        return trim($str);
    }
    
	/**
	 *  get the xoops site disclaimer via json
	 *
	 * @return string
	 */			
	function network_disclaimer(){

		$data = file_get_contents(sprintf(XORTIFY_REST_API, 'xoops_network_disclaimer', http_build_query(array("username"=> $this->json_xoops_username, "password"=> $this->json_xoops_password))));
			$result = $this->obj2array(json_decode($data));	

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
		$data = file_get_contents(sprintf(XORTIFY_REST_API, 'xoops_create_user', http_build_query(array("username"=> $this->json_xoops_username, "password"=> $this->json_xoops_password, "user" => array('user_viewemail' =>$user_viewemail, 'uname' => $uname, 'email' => $email, 'url' => $url, 'actkey' => $actkey, 'pass' => $pass, 'timezone_offset' => $timezone_offset, 'user_mailok' => $user_mailok, "time" => time(), "passhash" => sha1((time()-$rnd).$uname.$pass), "rand"=>$rnd), "siteinfo" => $siteinfo))));
			$result = $this->obj2array(json_decode($data));	

		if ($result['ERRNUM']==1){

			return $result["RESULT"];
			
		} else {
			return false;
		}
	}
		
	function obj2array($objects) {
		$ret = array();
		foreach($objects as $key => $value) {
			if (is_a($value, 'stdClass')) {
				$ret[$key] = (array)$value;
			} elseif (is_array($value)) {
				$ret[$key] = $this->obj2array($value);
			} else {
				$ret[$key] = $value;
			}
		}
		return $ret;
	}
}
// end class


?>
