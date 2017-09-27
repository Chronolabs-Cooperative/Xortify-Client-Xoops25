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
 * This File:	post.loader.php		
 * Description:	Spider post loader provider for Xortify and spiders module
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */


$module_handler =& xoops_gethandler('module');
$config_handler =& xoops_gethandler('config');
$GLOBALS['spiderModule'] = $module_handler->getByDirname('spiders');
if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
if (is_object($GLOBALS['spiderModule'])) {
	$GLOBALS['spidersModuleConfig'] = $config_handler->getConfigList($GLOBALS['spiderModule']->mid());

	if (is_object($GLOBALS['xoopsUser'])) {
		if (in_array($GLOBALS['spidersModuleConfig']['bot_group'], $GLOBALS['xoopsUser']->getGroups())&&!empty($_POST)) {

			include_once XOOPS_ROOT_PATH."/include/common.php";
			
			xoops_loadLanguage('ban', 'xortify');
			
			$log_handler = xoops_getmodulehandler('log', 'xortify');
			$log = $log_handler->create();
			$log->setVars(xortify_getIPData(false));
			$log->setVar('provider', basename(dirname(__FILE__)));
			$log->setVar('action', 'monitored');
			$log->setVar('extra', _XOR_BAN_SPIDER_TYPE.': '.print_r($_POST, true));
			$lid = $log_handler->insert($log, true);
			$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
			setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
			@xortifyDisplayBan();
		}
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['_pass'] = true;
	}	
}

?>