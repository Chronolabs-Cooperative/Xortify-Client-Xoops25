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
 * This File:	provider.php		
 * Description:	Boot strapping class for Providers with Xoritfy Client
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

if (!defined('XOOPS_ROOT_PATH')) die ('Restricted Access');



include_once( XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php' );
include_once( XOOPS_ROOT_PATH.'/modules/xortify/include/instance.php' );
include_once( XOOPS_ROOT_PATH.'/modules/xortify/language/english/modinfo.php' );

class Providers 
{
	var $providers = array();
	
	function init($check) {
		
		defined('DS') or define('DS', DIRECTORY_SEPARATOR);
		defined('NWLINE')or define('NWLINE', "\n");
		
		global $xoops, $xoopsPreload, $xoopsLogger, $xoopsErrorHandler, $xoopsSecurity, $sess_handler, $xoopsConfig;
		
		include_once XOOPS_ROOT_PATH . DS . 'include' . DS . 'defines.php';
		include_once XOOPS_ROOT_PATH . DS . 'include' . DS . 'version.php';
		include_once XOOPS_ROOT_PATH . DS . 'include' . DS . 'license.php';
		require_once XOOPS_ROOT_PATH . DS . 'class' . DS . 'cache' . DS . 'xoopscache.php';
		require_once XOOPS_ROOT_PATH . DS . 'class' . DS . 'xoopsload.php';
		
		$GLOBALS['xoopsCache'] = new XoopsCache();
		$GLOBALS['xoopsLoad'] = new XoopsLoad();
		
		$GLOBALS['xoopsLoad']->load('preload');
		$xoopsPreload =& XoopsPreload::getInstance();
		
		$GLOBALS['xoopsLoad']->load('xoopskernel');
		$xoops = new xos_kernel_Xoops2();
		$xoops->pathTranslation();
		$xoopsRequestUri =& $_SERVER['REQUEST_URI'];// Deprecated (use the corrected $_SERVER variable now)
		
		$GLOBALS['xoopsLoad']->load('xoopssecurity');
		$xoopsSecurity = new XoopsSecurity();
		$xoopsSecurity->checkSuperglobals();
		
		$GLOBALS['xoopsLoad']->load('xoopslogger');
		$xoopsLogger =& XoopsLogger::getInstance();
		$xoopsErrorHandler =& XoopsLogger::getInstance();
		
		include_once $xoops->path('kernel/object.php');
		include_once $xoops->path('class/criteria.php');
		include_once $xoops->path('class/module.textsanitizer.php');
		include_once $xoops->path('include/functions.php');
		
		include_once $xoops->path('class/database/databasefactory.php');
		$GLOBALS['xoopsDB'] =& XoopsDatabaseFactory::getDatabaseConnection();
		
		/**
		 * Get xoops configs
		 * Requires functions and database loaded
		 */
		$config_handler =& xoops_gethandler('config');
		$xoopsConfig = $config_handler->getConfigsByCat(XOOPS_CONF);
		
		/**
		 * User Sessions
		 */
		$xoopsUser = '';
		$xoopsUserIsAdmin = false;
		$member_handler =& xoops_gethandler('member');
		$sess_handler =& xoops_gethandler('session');
		if ($xoopsConfig['use_ssl']
				&& isset($_POST[$xoopsConfig['sslpost_name']])
				&& $_POST[$xoopsConfig['sslpost_name']] != ''
		) {
			session_id($_POST[$xoopsConfig['sslpost_name']]);
		} else if ($xoopsConfig['use_mysession'] && $xoopsConfig['session_name'] != '' && $xoopsConfig['session_expire'] > 0) {
			if (isset($_COOKIE[$xoopsConfig['session_name']])) {
				session_id($_COOKIE[$xoopsConfig['session_name']]);
			}
			if (function_exists('session_cache_expire')) {
				session_cache_expire($xoopsConfig['session_expire']);
			}
			@ini_set('session.gc_maxlifetime', $xoopsConfig['session_expire'] * 60);
		}
		session_set_save_handler(array(&$sess_handler, 'open'),
		array(&$sess_handler, 'close'),
		array(&$sess_handler, 'read'),
		array(&$sess_handler, 'write'),
		array(&$sess_handler, 'destroy'),
		array(&$sess_handler, 'gc'));
		if (strlen(session_id())==0)
			session_start();
		
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');	
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))		
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
		
		global $xoopsConfig; 
		$xoopsConfig = $config_handler->getConfigsByCat(XOOPS_CONF);
	}
		
	function __construct($check = 'precheck')
	{	 
				
		if (strpos($_SERVER["PHP_SELF"], '/banned.php')>0) {
			return false;
		}
		
		$this->init($check);	
		$this->providers = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_providers'];
		
		$this->$check();
	}
	
	private function precheck()
	{
		
		
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			return false;
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('version')<305)
			return false;
		foreach($this->providers as $id => $key)
		switch ($key) {
		default:
			
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/precheck.inc.php')) 
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/precheck.inc.php');
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/pre.loader.php')) 
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/pre.loader.php');
			
		}
		
	}
	
	private function postcheck()
	{
		
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			return false;
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('version')<305)
			return false;
		foreach($this->providers as $id => $key)
		switch ($key) {
		default:
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/postcheck.inc.php'))
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/postcheck.inc.php');
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/post.loader.php'))
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/post.loader.php');
		}
		
	}
	
	private function headerpostcheck()
	{
		
		
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			return false;
		
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('version')<305)
			return false;
		foreach($this->providers as $id => $key)
		switch ($key) {
		default:
			
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/headerpostcheck.inc.php'))
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/headerpostcheck.inc.php');
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/header.post.loader.php'))
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/header.post.loader.php');
			
		}
		
	}
	
	private function footerpostcheck()
	{
		
		
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('version')<305)
			return false;
		foreach($this->providers as $id => $key)
		switch ($key) {
		default:
			
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/footerpostcheck.inc.php'))
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/footerpostcheck.inc.php');
			if (file_exists(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/footer.post.loader.php'))
				include_once(XOOPS_ROOT_PATH.'/modules/xortify/providers/'.$key.'/footer.post.loader.php');
			
		}
		
	}
}

?>