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
 * This File:	authfactory.php		
 * Description:	Auth Factory Library with Packages for signup and API
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

if (!class_exists('XortifyAuthFactory')) {
	class XortifyAuthFactory
	{
	
		/**
		 * Get a reference to the only instance of authentication class
		 * 
		 * if the class has not been instantiated yet, this will also take 
		 * care of that
		 * 
		 * @static
		 * @return      object  Reference to the only instance of authentication class
		 */
		function &getAuthConnection($uname, $xortify_auth_method = 'soap')
		{
					
			static $auth_instance;		
			if (!isset($auth_instance)) {
				require_once XOOPS_ROOT_PATH.'/modules/xortify/class/auth/auth.php';
				// Verify if uname allow to bypass LDAP auth 
				$file = XOOPS_ROOT_PATH . '/modules/xortify/class/auth/auth_' . $xortify_auth_method . '.php';			
				require_once $file;
				$class = 'XortifyAuth' . ucfirst($xortify_auth_method);
				switch ($xortify_auth_method) {
					case 'soap';
						$dao = null;
						break;
	
				}
				$auth_instance = new $class($GLOBALS['xoopsDB'], XOOPS_URL);
			}
			return $auth_instance;
		}
	
	}
}
?>
