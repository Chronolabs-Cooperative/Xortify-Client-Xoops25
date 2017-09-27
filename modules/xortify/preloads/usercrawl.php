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
 * This File:	core.php		
 * Description:	Preloader Hooking Stratum for Xortify Client
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

defined('XOOPS_ROOT_PATH') or die('Restricted access');

include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
include_once XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php';
include_once XOOPS_ROOT_PATH.'/modules/xortify/include/instance.php';

class XortifyUsercrawlPreload extends XoopsPreloadItem
{
	
	static function eventUsercrawlHeaderCacheEnd($args)
	{
		self::eventUsercrawlFooterEnd($args);
	}

	static function eventUsercrawlFooterEnd($args)
	{
		if (self::hasAPIUserPass()==false)
			return false;
		
		xoops_loadLanguage('modinfo', 'xortify');
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');		
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
		
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['users_to_check']==0)
			return false;
		
		$usercrawl = $GLOBALS['xoopsCache']->read('xortify_usercrawl_last');
		if ((isset($usercrawl['when'])?(float)$usercrawl['when']:-microtime(true))+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']<=microtime(true)) {
			$usercrawl['when'] = microtime(true);
			$user_handler = xoops_gethandler('user');
			if (count($usercrawl['users'])) {
				$criteria = new Criteria('uid', 'NOT IN', '('.implode(',', $usercrawl['users']) .')');
				$criteria->setSort('RAND()');
				$criteria->setLimit($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['users_to_check']);
			} elseif (count($result['users'])==0) {
				$criteria = new Criteria('uid', '<>', '0');
				$criteria->setSort('RAND()');
				$criteria->setLimit($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['users_to_check']);
			}
			$users = $user_handler->getObjects($criteria, true, true);
			
			if (count($users)<$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['users_to_check']) {
				$usercrawl['users'] = array();
			} else {
				$usercrawl['users'] = array_merge($usercrawl['users'], array_keys($users));
			}
			
			require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol'].'.php' );
			$func = strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']).'XortifyExchange';
			$apiExchange = new $func;
			
			$sfs = array();
			$seconds = 120;
			foreach($users as $uid => $user) {
				$seconds = $seconds + microtime(true) - $end;
				set_time_limit($seconds);
				$sfs[$uid] = $apiExchange->checkSFSBans($user);
				$end = microtime(true);
			}
			
			$uids = array();
			foreach($sfs as $uid => $result) {
				$seconds = $seconds + microtime(true) - $end;
				set_time_limit($seconds);				
				if (is_array($result)) {
					if (isset($result['success']))
						if ($result['success']==true)
						if (($result['email']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_freq']||$result['username']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_freq']||$result['ip']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_freq']) &&
								(strtotime($result['email']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_lastseen']||strtotime($result['username']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_lastseen']||strtotime($result['ip']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_lastseen'])) {
							
						include_once XOOPS_ROOT_PATH."/include/common.php";
							
						$GLOBALS['xoopsCache']->write('xortify_sfs_'.sha1($users[$uid]['uname'].$users[$uid]['email'].(isset($users[$uid]['ip4'])?$users[$uid]['ip4']:"").(isset($users[$uid]['ip6'])?$users[$uid]['ip6']:"").(isset($users[$uid]['proxy-ip4'])?$users[$uid]['proxy-ip4']:"").(isset($users[$uid]['proxy-ip4'])?$users[$uid]['proxy-ip6']:"").$users[$uid]['network-addy']), array_merge($result, array('ipdata' => $users[$uid])), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);
							
						xoops_loadLanguage('ban', 'xortify');
							
						$log_handler = xoops_getmodulehandler('log', 'xortify');
						$log = $log_handler->create();
						$log->setVars($ipdata);
						$log->setVar('provider', 'stopforumspam.com');
						$log->setVar('action', 'banned');
						$log->setVar('extra', _XOR_BAN_SFS_TYPE."\n".
								_XOR_BAN_SFS_EMAIL_FREQ.': '.$result['email']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_freq']. "\n".
								_XOR_BAN_SFS_EMAIL_LASTSEEN.': '.date(_DATESTRING, strtotime($result['email']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_lastseen']) . "\n" .
								_XOR_BAN_SFS_USERNAME_FREQ.': '.$result['username']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_freq']. "\n".
								_XOR_BAN_SFS_USERNAME_LASTSEEN.': '.date(_DATESTRING, strtotime($result['username']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_lastseen']) . "\n" .
								_XOR_BAN_SFS_IP_FREQ.': '.$result['ip']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_freq']. "\n".
								_XOR_BAN_SFS_IP_LASTSEEN.': '.date(_DATESTRING, strtotime($result['ip']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_lastseen']));

						$uids[$uid] = $uid;
					}
				}
				$end = microtime(true);
			}

			if (count($uids)>0) {
				$criteria = criteria('uid', 'IN', '('.implode(', ', array_keys($uids)).')');
				$user_handler->deleteAll($criteria);
			}
			$usercrawl['deleted'] = $usercrawl['deleted'] + count($uids);
			
			$usercrawl['took'] = microtime(true)-$usercrawl['when'];
			$GLOBALS['xoopsCache']->write('xortify_usercrawl_last', $usercrawl, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']*2);
		}
		
		return true;
	}
	
	static function hasAPIUserPass()
	{
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_username']!=''&&$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_password']!='')
			return true;
		else
			return false;
	}		
	
}

?>