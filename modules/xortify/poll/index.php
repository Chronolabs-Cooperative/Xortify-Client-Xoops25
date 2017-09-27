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
* Download:		http://sourceforge.net/projects/xortify
* This File:	index.php
* Description:	Data Push recieving service from Xortify Cloud.
* Date:			06-Jan-2015 03:45 AEST
* License:		GNU3
*
*/
	
	global $xoops, $xoopsPreload, $xoopsLogger, $xoopsErrorHandler, $xoopsSecurity, $sess_handler;

	session_id($_REQUEST['session']);
	session_start();
	
	$xoopsOption["nocommon"]=true;
	require_once(dirname(dirname(dirname(dirname(__FILE__)))).'/mainfile.php');
	require_once(dirname(dirname(__FILE__)).'/language/english/modinfo.php');
	require_once(dirname(dirname(__FILE__)).'/xoops_version.php');
	
	if (_MI_XOR_MODE!=_MI_XOR_MODE_CLIENT)
		die(_MI_XOR_NOT_MODE_CLIENT);
	
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
	
	$module_handler = xoops_gethandler('module');
	$config_handler = xoops_gethandler('config');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid')); 
	
	include_once $GLOBALS['xoops']->path('class'.DS.'cache'.DS.'xoopscache.php');
	
	if ($GLOBALS['xoopsSecurity']->validateToken($_REQUEST['token'], true, 'poll_token')==true) {
		$GLOBALS['xoopsCache']->write($_REQUEST['carriage'], $_REQUEST['data'], (integer)$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'][$_REQUEST['config']]);
		echo serialize(array('success'=>true));
		exit;
	}
	echo serialize(array('success'=>false));
	exit;
	
?>