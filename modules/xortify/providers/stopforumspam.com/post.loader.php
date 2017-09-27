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
 * Description:	Stop Forum Spam Post loader provider for Xortify Client
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */
	
	include_once($GLOBALS['xoops']->path('/modules/xortify/include/functions.php'));
	
	xoops_load('xoopscache');
	if (!class_exists('XoopsCache')) {
		// XOOPS 2.4 Compliance
		xoops_load('cache');
		if (!class_exists('XoopsCache')) {
			include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
		}
	}
	
	
	
	$ipdata = xortify_getIPData(false);
	
	if (isset($ipdata['ip4']))
		if ($ipdata['ip4']==$GLOBALS['xoopsConfig']['my_ip'])
			return false;
			
	if (isset($ipdata['ip6']))
		if ($ipdata['ip6']==$GLOBALS['xoopsConfig']['my_ip']) 
			return false;
	
	$checked = $GLOBALS['xoopsCache']->read('xortify_sfs_'.sha1($ipdata['uname'].$ipdata['email'].(isset($ipdata['ip4'])?$ipdata['ip4']:"").(isset($ipdata['ip6'])?$ipdata['ip6']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip4']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip6']:"").$ipdata['network-addy']));
	
	$module_handler = xoops_gethandler('module');
	$config_handler = xoops_gethandler('config');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module'] = $module_handler->getByDirname('xortify');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['module']->getVar('mid'));
	
	if (!is_array($checked))
	{
		
		require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['protocol'].'.php' );
		$func = strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['protocol']).'XortifyExchange';
		ob_start();
		$apiExchange = new $func;
		
		$result = $apiExchange->checkSFSBans($ipdata);
		
		ob_end_flush();
		
		if (is_array($result)) {
			if (!isset($result['success']))
				$result['success']==false;
			if (isset($result['success']))
				if ($result['success']==true)
					if (($result['email']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_freq']||$result['username']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_freq']||$result['ip']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_freq']) &&
						(strtotime($result['email']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_lastseen']||strtotime($result['username']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_lastseen']||strtotime($result['ip']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_lastseen'])) {
							
							include_once XOOPS_ROOT_PATH."/include/common.php";
							
							$GLOBALS['xoopsCache']->write('xortify_sfs_'.sha1($ipdata['uname'].$ipdata['email'].(isset($ipdata['ip4'])?$ipdata['ip4']:"").(isset($ipdata['ip6'])?$ipdata['ip6']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip4']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip6']:"").$ipdata['network-addy']), array_merge($result, array('ipdata' => $ipdata)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['xortify_ip_cache']);					
							
							xoops_loadLanguage('ban', 'xortify');
							
							$result = $apiExchange->sendBan(_XOR_BAN_SFS_TYPE."\n".
														  _XOR_BAN_SFS_EMAIL_FREQ.': '.$result['email']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_freq']. "\n".
														  _XOR_BAN_SFS_EMAIL_LASTSEEN.': '.date(_DATESTRING, strtotime($result['email']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_lastseen']) . "\n" .
														  _XOR_BAN_SFS_USERNAME_FREQ.': '.$result['username']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_freq']. "\n".
														  _XOR_BAN_SFS_USERNAME_LASTSEEN.': '.date(_DATESTRING, strtotime($result['username']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_lastseen']) . "\n" .
														  _XOR_BAN_SFS_IP_FREQ.': '.$result['ip']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_freq']. "\n".
														  _XOR_BAN_SFS_IP_LASTSEEN.': '.date(_DATESTRING, strtotime($result['ip']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_lastseen']), 4, $ipdata);
 						    
							$log_handler = xoops_getmodulehandler('log', 'xortify');
							$log = $log_handler->create();
							$log->setVars($ipdata);
							$log->setVar('provider', basename(dirname(__FILE__)));
							$log->setVar('action', 'banned');
							$log->setVar('extra', $_SESSION['xortify']['banText'] = _XOR_BAN_SFS_TYPE."\n".
												  _XOR_BAN_SFS_EMAIL_FREQ.': '.$result['email']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_freq']. "\n".
												  _XOR_BAN_SFS_EMAIL_LASTSEEN.': '.date(_DATESTRING, strtotime($result['email']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_lastseen']) . "\n" .
												  _XOR_BAN_SFS_USERNAME_FREQ.': '.$result['username']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_freq']. "\n".
												  _XOR_BAN_SFS_USERNAME_LASTSEEN.': '.date(_DATESTRING, strtotime($result['username']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_lastseen']) . "\n" .
												  _XOR_BAN_SFS_IP_FREQ.': '.$result['ip']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_freq']. "\n".
												  _XOR_BAN_SFS_IP_LASTSEEN.': '.date(_DATESTRING, strtotime($result['ip']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_lastseen']));
							$lid = $log_handler->insert($log, true);
							$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['fault_delay']);
							$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
							setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
							@xortifyDisplayBan();
							
						}
			unlinkOldCachefiles('xortify_',$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['xortify_ip_cache']);
			$GLOBALS['xoopsCache']->write('xortify_sfs_'.sha1($ipdata['uname'].$ipdata['email'].(isset($ipdata['ip4'])?$ipdata['ip4']:"").(isset($ipdata['ip6'])?$ipdata['ip6']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip4']:"").(isset($ipdata['proxy-ip4'])?$ipdata['proxy-ip6']:"").$ipdata['network-addy']), array_merge($result, array('ipdata' => $ipdata)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['xortify_ip_cache']);
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['_pass'] = true;
				
		}	
	} elseif (isset($checked['success'])&&$checked['success']==true) {
		if (($checked['email']['frequency']>=2||$checked['username']['frequency']>=2||$checked['ip']['frequency']>=2) &&
			(strtotime($checked['email']['lastseen'])>time()-(60*60*24*7*4*3)||strtotime($checked['username']['lastseen'])>time()-(60*60*24*7*4*3)||strtotime($checked['ip']['lastseen'])>time()-(60*60*24*7*4*3))) {
				
				include_once XOOPS_ROOT_PATH."/include/common.php";
				
				xoops_loadLanguage('ban', 'xortify');
				
				$log_handler = xoops_getmodulehandler('log', 'xortify');
				$log = $log_handler->create();
				$log->setVars($ipdata);
				$log->setVar('provider', basename(dirname(__FILE__)));
				$log->setVar('action', 'blocked');
				$log->setVar('extra', $_SESSION['xortify']['banText'] = _XOR_BAN_SFS_TYPE."\n".
									  _XOR_BAN_SFS_EMAIL_FREQ.': '.$checked['email']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_freq']. "\n".
									  _XOR_BAN_SFS_EMAIL_LASTSEEN.': '.date(_DATESTRING, strtotime($checked['email']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['email_lastseen']) . "\n" .
									  _XOR_BAN_SFS_USERNAME_FREQ.': '.$checked['username']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_freq']. "\n".
									  _XOR_BAN_SFS_USERNAME_LASTSEEN.': '.date(_DATESTRING, strtotime($checked['username']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['uname_lastseen']) . "\n" .
									  _XOR_BAN_SFS_IP_FREQ.': '.$checked['ip']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_freq']. "\n".
									  _XOR_BAN_SFS_IP_LASTSEEN.': '.date(_DATESTRING, strtotime($checked['ip']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['ip_lastseen']));
				$lid = $log_handler->insert($log, true);
				$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['moduleConfig']['fault_delay']);
				$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
				setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
				@xortifyDisplayBan();
				
				
		}
	}
	
?>