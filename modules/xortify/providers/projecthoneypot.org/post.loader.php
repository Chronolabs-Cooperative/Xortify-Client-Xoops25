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
 * Description:	Project Honeypot Provider Post Loader
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */
	
	
	include_once($GLOBALS['xoops']->path('/modules/xortify/include/functions.php'));
	
	if (is_object($GLOBALS['xoopsUser'])) {
		$uid = $GLOBALS['xoopsUser']->getVar('uid');
		$uname = $GLOBALS['xoopsUser']->getVar('uname');
		$email = $GLOBALS['xoopsUser']->getVar('email');
	} else {
		$uid = 0;
		$uname = (isset($_REQUEST['uname'])?$_REQUEST['uname']:'');
		$email = (isset($_REQUEST['email'])?$_REQUEST['email']:'');
	}
	
	$module_handler = xoops_gethandler('module');
	$config_handler = xoops_gethandler('config');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
	
	xoops_load('xoopscache');
	if (!class_exists('XoopsCache')) {
		// XOOPS 2.4 Compliance
		xoops_load('cache');
		if (!class_exists('XoopsCache')) {
			include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
		}
	}
	
	if (!$ipdata = $GLOBALS['xoopsCache']->read('xortify_php_'.sha1($_SERVER['REMOTE_ADDR'].(isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:'').$uid.$uname.$email))) {
		$ipdata = xortify_getIPData(false);
		$GLOBALS['xoopsCache']->write('xortify_php_'.sha1($_SERVER['REMOTE_ADDR'].(isset($_SERVER['HTTP_X_FORWARDED_FOR'])?$_SERVER['HTTP_X_FORWARDED_FOR']:'').$uid.$uname.$email), $ipdata, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);
	}
	
	if (isset($ipdata['ip4']))
		if ($ipdata['ip4']==$GLOBALS['xoopsConfig']['my_ip'])
			return false;
			
	if (isset($ipdata['ip6']))
		if ($ipdata['ip6']==$GLOBALS['xoopsConfig']['my_ip']) 
			return false;
	
	$checked = $GLOBALS['xoopsCache']->read('xortify_php_'.sha1($ipdata['uname'].$ipdata['email'].(isset($ipdata['ip4'])?$ipdata['ip4']:"").(isset($ipdata['ip6'])?$ipdata['ip6']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip4']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip6']:"").$ipdata['network-addy']));
		
  	
	if (!is_array($checked))
	{
		require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol'].'.php' );
		$func = strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']).'XortifyExchange';
		ob_start();
		$apiExchange = new $func;
		$result = $apiExchange->checkPHPBans($ipdata);
		ob_end_flush();
		if (is_array($result)) {
			if (!isset($result['success']))
				$result['success']==false;
			if ($result['success']==true)
				if (($result['octeta']<=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octeta']&&$result['octetb']>$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetb']&&$result['octetc']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetc'])) {
					$module_handler =& xoops_gethandler('module');
					$config_handler =& xoops_gethandler('config');
					if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
					$configs = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->mid());
					
					$GLOBALS['xoopsCache']->write('xortify_php_'.sha1($ipdata['uname'].$ipdata['email'].(isset($ipdata['ip4'])?$ipdata['ip4']:"").(isset($ipdata['ip6'])?$ipdata['ip6']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip4']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip6']:"").$ipdata['network-addy']), array_merge($result, array('ipdata' => $ipdata)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);					
				
					xoops_loadLanguage('ban', 'xortify');
					
					$result = $apiExchange->sendBan(_XOR_BAN_PHP_TYPE."\n".
												  _XOR_BAN_PHP_OCTETA.' '.$result['octeta'].' <= ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octeta']."\n".
												  _XOR_BAN_PHP_OCTETB.' '.$result['octetb'].' > ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetb']."\n".
												  _XOR_BAN_PHP_OCTETC.' '.$result['octetc'].' >= ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetc']."\n", 5, $ipdata);
												  
					$log_handler = xoops_getmodulehandler('log', 'xortify');
					$log = $log_handler->create();
					$log->setVars($ipdata);
					$log->setVar('provider', basename(dirname(__FILE__)));
					$log->setVar('action', 'banned');
					$log->setVar('extra', $_SESSION['xortify']['banText'] = _XOR_BAN_PHP_OCTETA.' '.$result['octeta'].' <= ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octeta']."\n".
										  _XOR_BAN_PHP_OCTETB.' '.$result['octetb'].' > ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetb']."\n".
										  _XOR_BAN_PHP_OCTETC.' '.$result['octetc'].' >= ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetc']);
					
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $log_handler->insert($log, true);
					$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
					setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
					@xortifyDisplayBan();
				
				}
			
		}
		unlinkOldCachefiles('xortify_',$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['_pass'] = true;
		$GLOBALS['xoopsCache']->write('xortify_php_'.sha1($ipdata['uname'].$ipdata['email'].(isset($ipdata['ip4'])?$ipdata['ip4']:"").(isset($ipdata['ip6'])?$ipdata['ip6']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip4']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip6']:"").$ipdata['network-addy']), array_merge($result, array('ipdata' => $ipdata)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_seconds']);
		
	} elseif (isset($checked['success'])) {
		if (!isset($checked['success']))
			$checked['success']==false;
		if ($checked['success']==true) {
			if (($checked['octeta']<=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octeta']&&$checked['octetb']>$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetb']&&$checked['octetc']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetc'])) {
				
				xoops_loadLanguage('ban', 'xortify');
				
				$log_handler = xoops_getmodulehandler('log', 'xortify');
				$log = $log_handler->create();
				$log->setVars($ipdata);
				$log->setVar('provider', basename(dirname(__FILE__)));
				$log->setVar('action', 'blocked');
				$log->setVar('extra', $_SESSION['xortify']['banText'] = _XOR_BAN_PHP_OCTETA.' '.$checked['octeta'].' <= ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octeta']."\n".
									  _XOR_BAN_PHP_OCTETB.' '.$checked['octetb'].' > ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetb']."\n".
									  _XOR_BAN_PHP_OCTETC.' '.$checked['octetc'].' >= ' . $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['octetc']);
				
				$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $log_handler->insert($log, true);
				$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
				$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
				setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
				@xortifyDisplayBan();			
			}
		}
	}
	
?>