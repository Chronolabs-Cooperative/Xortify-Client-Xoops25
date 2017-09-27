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
 * This File:	serverup.php		
 * Description:	Cron job for Xortify Module
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

	include_once dirname(dirname(dirname(dirname(__FILE__)))).'/mainfile.php';
	include_once dirname(dirname(__FILE__)).'/include/functions.php';
	
	function xortify_getURLData($URI, $curl=false) {
		$ret = '';
		try {
			switch ($curl) {
				case true:
					if (!$ch = curl_init($URI)) {
						trigger_error('Could not intialise CURL file: '.$url);
						return false;
					}
					$cookies = XOOPS_VAR_PATH.'/cache/xoops_cache/croncurl_'.md5($URI).'.cookie'; 
			
					curl_setopt($ch, CURLOPT_HEADER, 0);
					curl_setopt($ch, CURLOPT_COOKIEJAR, $cookies);
					curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['curl_connecttimeout']);
					curl_setopt($ch, CURLOPT_TIMEOUT, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['curl_timeout']);
					curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); 
					curl_setopt($ch, CURLOPT_USERAGENT, XORTIFY_USER_AGENT);
					$ret = curl_exec($ch);
					curl_close($ch);
					break;
				case false:
					$ret = file_get_contents($uri);
					break;
				
			}
		}
		catch(Exception $e) {
			echo 'Exception: "'.$e."\n";
		}	
		return $ret;
	}
	
	foreach (get_loaded_extensions() as $ext){
		if ($ext=="curl")
			$nativecurl=true;
	}

	global $xoops, $xoopsPreload, $xoopsLogger, $xoopsErrorHandler, $xoopsSecurity, $sess_handler;
	
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['_preloader'])) {
		$xoopsOption["nocommon"]=true;
		require_once(dirname(dirname(dirname(dirname(__FILE__)))).'/mainfile.php');
		
		defined('DS') or define('DS', DIRECTORY_SEPARATOR);
		defined('NWLINE')or define('NWLINE', "\n");
		
		include_once XOOPS_ROOT_PATH . DS . 'include' . DS . 'defines.php';
		include_once XOOPS_ROOT_PATH . DS . 'include' . DS . 'version.php';
		include_once XOOPS_ROOT_PATH . DS . 'include' . DS . 'license.php';
		
		require_once XOOPS_ROOT_PATH . DS . 'class' . DS . 'xoopsload.php';
		
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
		$xoopsLogger->startTime();
		$xoopsLogger->startTime('XOOPS Boot');
		
		include_once $xoops->path('kernel/object.php');
		include_once $xoops->path('class/criteria.php');
		include_once $xoops->path('class/module.textsanitizer.php');
		include_once $xoops->path('include/functions.php');
		
		include_once $xoops->path('class/database/databasefactory.php');
		$GLOBALS['xoopsDB'] =& XoopsDatabaseFactory::getDatabaseConnection();
	}
	
	define("SOAP", 'soap/');
	define("CURL", 'curl/');
	define("JSON", 'json/');
	define("SERIAL", 'serial/');
	define("XML", 'xml/');
	define("REST", 'api/');
	
	include_once $xoops->path('class/cache/xoopscache.php');
	
	$module_handler =& xoops_gethandler('module');
	$config_handler =& xoops_gethandler('config');
	$configitem_handler =& xoops_gethandler('configitem');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']))
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module'] = $module_handler->getByDirname('xortify');
	
	if (!defined('XORTIFY_USER_AGENT'))
		define('XORTIFY_USER_AGENT', 'Mozilla/5.0 ('.XOOPS_VERSION.'; PHP '.PHP_VERSION.') Xortify ' . ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('version')/100));
	
	$serverup=false;
	if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module'])) {
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid'));
		if ($servers = $GLOBALS['xoopsCache']->read('server_list_xortify')) {
			foreach($servers as $sid => $server) {
				$source = xortify_getURLData($server['server'], $nativecurl);
				if (strpos(strtolower($source), strtolower($server['search']))>0) {
					$serverup=true;
					$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid')));
					$criteria->add(new Criteria('conf_name', 'xortify_urisoap'));
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $configitem_handler->getObjects($criteria);
					if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0])) {
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0]->setVar('conf_value', str_replace($server['replace'], SOAP, $server['server']));
						$configitem_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0], true);
					}
					$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid')));
					$criteria->add(new Criteria('conf_name', 'xortify_uricurl'));
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $configitem_handler->getObjects($criteria);
					if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0])) {
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0]->setVar('conf_value', str_replace($server['replace'], CURL, $server['server']));
						$configitem_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0], true);
					}
					$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid')));
					$criteria->add(new Criteria('conf_name', 'xortify_urijson'));
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $configitem_handler->getObjects($criteria);
					if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0])) {
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0]->setVar('conf_value', str_replace($server['replace'], JSON, $server['server']));
						$configitem_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0], true);
					}
					$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid')));
					$criteria->add(new Criteria('conf_name', 'xortify_uriserial'));
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $configitem_handler->getObjects($criteria);
					if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0])) {
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0]->setVar('conf_value', str_replace($server['replace'], SERIAL, $server['server']));
						$configitem_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0], true);
					}
					$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid')));
					$criteria->add(new Criteria('conf_name', 'xortify_urixml'));
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $configitem_handler->getObjects($criteria);
					if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0])) {
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0]->setVar('conf_value', str_replace($server['replace'], XML, $server['server']));
						$configitem_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0], true);
					}
					$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid')));
					$criteria->add(new Criteria('conf_name', 'xortify_urirest'));
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $configitem_handler->getObjects($criteria);
					if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0])) {
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0]->setVar('conf_value', str_replace($server['replace'], REST, $server['server']));
						$configitem_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'][0], true);
					}				
				}
			}
		}
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->setVar('isactive', $serverup);
		$module_handler->insert($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module'], true);
	}
	
	unlinkOldCachefiles('xortify_',$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['xortify_ip_cache']);	
?>