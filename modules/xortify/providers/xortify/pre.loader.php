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
 * This File:	pre.loader.php		
 * Description:	Xortify Pre Loader Provider for Client
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

	$module_handler = xoops_gethandler('module');
	$config_handler = xoops_gethandler('config');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']))
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
	
	xoops_load('xoopscache');
	if (!class_exists('XoopsCache')) {
		// XOOPS 2.4 Compliance
		xoops_load('cache');
		if (!class_exists('XoopsCache')) {
			include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
		}
	}
	
	if (!$servers = $GLOBALS['xoopsCache']->read('server_list_xortify')) {
		require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol'].'.php' );
		$func = strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']).'XortifyExchange';
		$apiExchange = new $func;
		@$poll = $apiExchange->getServers();
		if (!isset($poll['success'])||$poll['success']==false) {
			$GLOBALS['xoopsCache']->write('server_list_xortify', array(0=>array('server'=>'http://xortify.com/unban/?op=unban', 'replace' => 'unban/?op=unban', 'search' => 'Solve Puzzel:'), 1=>array('server'=>'http://xortify.xoops.org/unban/?op=unban', 'replace' => 'unban/?op=unban', 'search' => 'Solve Puzzel:')), (integer)$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['server_cache']);
		}
	}	

?>