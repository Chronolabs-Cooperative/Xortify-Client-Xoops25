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
 * This File:	update.php		
 * Description:	The Upgrade Routines.
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

function xoops_module_update_xortify(&$module) {
	
	$sql[] = "CREATE TABLE `".$GLOBALS['xoopsDB']->prefix('xortify_log')."` (
			  `lid` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
			  `uid` mediumint(8) unsigned NOT NULL DEFAULT '0',
			  `uname` varchar(64) DEFAULT NULL,
			  `email` varchar(255) DEFAULT NULL,
			  `ip4` varchar(15) NOT NULL DEFAULT '0.0.0.0',
			  `ip6` varchar(128) NOT NULL DEFAULT '0:0:0:0:0:0',
			  `proxy-ip4` varchar(64) NOT NULL DEFAULT '0.0.0.0',
			  `proxy-ip6` varchar(128) NOT NULL DEFAULT '0:0:0:0:0:0',
			  `network-addy` varchar(255) NOT NULL DEFAULT '',
			  `provider` varchar(128) NOT NULL DEFAULT '',
			  `agent` varchar(255) NOT NULL DEFAULT '',
			  `extra` text,
			  `date` int(12) NOT NULL DEFAULT '0',
			  `action` enum('banned','blocked','monitored') NOT NULL DEFAULT 'monitored',
			  PRIMARY KEY (`lid`),
			  KEY `uid` (`uid`),
			  KEY `ip` (`ip4`,`ip6`(16),`proxy-ip4`,`proxy-ip6`(16)),
			  KEY `provider` (`provider`(15)),
			  KEY `date` (`date`),
			  KEY `action` (`action`)
			) ENGINE=INNODB DEFAULT CHARSET=utf8";

	$sql[] = "CREATE TABLE `".$GLOBALS['xoopsDB']->prefix('xortify_servers')."` (
			  `sid` mediumint(32) unsigned NOT NULL AUTO_INCREMENT,
			  `server` varchar(255) NOT NULL DEFAULT '',
			  `replace` varchar(255) NOT NULL DEFAULT '',
			  `search` varchar(64) NOT NULL DEFAULT '',
			  `online` tinyint(1) DEFAULT '0',
			  `polled` int(12) NOT NULL DEFAULT '0',
			  `user` varchar(64) NOT NULL DEFAULT '',
			  `pass` varchar(32) NOT NULL DEFAULT '',
			  PRIMARY KEY (`sid`)
			) ENGINE=INNODB DEFAULT CHARSET=utf8";
	

	$sql[] = "CREATE TABLE `".$GLOBALS['xoopsDB']->prefix('xortify_emails')."` (
			`eid` mediumint(32) unsigned NOT NULL AUTO_INCREMENT,
			`email` varchar(255) NOT NULL DEFAULT '',
			`uid` int(13) NOT NULL DEFAULT '0',
			`count` int(26) NOT NULL DEFAULT '1',
			`encounter` int(13) NOT NULL DEFAULT '0',
			PRIMARY KEY (`eid`)
			) ENGINE=INNODB DEFAULT CHARSET=utf8";
	
	$sql[] = "CREATE TABLE `".$GLOBALS['xoopsDB']->prefix('xortify_emails_links')."` (
			`elid` mediumint(64) unsigned NOT NULL AUTO_INCREMENT,
			`eid` mediumint(32) unsigned NOT NULL DEFAULT '0',
			`uid` int(13) NOT NULL DEFAULT '0',
			`ip` varchar(128) NOT NULL DEFAULT '127.0.0.1',
			PRIMARY KEY (`elid`)
			) ENGINE=INNODB DEFAULT CHARSET=utf8";
				
	foreach($sql as $id => $question)
		if ($GLOBALS['xoopsDB']->queryF($question))
			xoops_error($question, 'SQL Executed Successfully!!!');
			
	xoops_load("xoopscache");	
	$GLOBALS['xoopsCache']->delete('xortify_bans_protector');
	
	if (defined('XORTIFY_INSTANCE_KEY'))
		if (strlen(constant('XORTIFY_INSTANCE_KEY'))==0 ||
				constant('XORTIFY_INSTANCE_KEY')=='00000-00000-00000-00000-00000') {
			include_once $GLOBALS['xoops']->path('/modules/xortify/include/functions.php');
			$key = md5(XOOPS_LICENSE_KEY . microtime(true) . XOOPS_ROOT_PATH . XOOPS_VAR_PATH . XOOPS_DB_HOST . XOOPS_DB_NAME . XOOPS_DB_PREFIX . XOOPS_DB_USER . XOOPS_DB_PASS);
			$start = mt_rand(0, 31-25);
			if ($pos==5&&$i<24) {
				$instance .= mt_rand(0,3)<2?strtolower($key[$start+$i]):strtoupper($key[$start+$i]);
				$pos++;
				if ($pos==5) {
					$pos=0;
					$instance .= '-';
				}
			}
			if (writeInstanceKey($instance)==false) {
				xoops_error(_XOR_MI_XORTIFY_INSTANCE_KEY_WASNOTWRITTEN);
			}
		}
		
	$module_handler =& xoops_gethandler('module');
	$config_handler =& xoops_gethandler('config');
	$configitem_handler =& xoops_gethandler('configitem');
	if (!is_object($GLOBALS['protector']))
		$GLOBALS['protector'] = $module_handler->getByDirname('protector');
	
	if (!empty($GLOBALS['protector'])) {
	
		$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['protector']->getVar('mid')));
		$criteria->add(new Criteria('conf_name', 'contami_action'));
		$GLOBALS['protectorConfig'] = $configitem_handler->getObjects($criteria);
		if (isset($GLOBALS['protectorConfig'][0])) {
			$GLOBALS['protectorConfig'][0]->setVar('conf_value', 15);
			$configitem_handler->insert($GLOBALS['protectorConfig'][0], true);
		}
	
	
		$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['protector']->getVar('mid')));
		$criteria->add(new Criteria('conf_name', 'isocom_action'));
		$GLOBALS['protectorConfig'] = $configitem_handler->getObjects($criteria);
		if (isset($GLOBALS['protectorConfig'][0])) {
			$GLOBALS['protectorConfig'][0]->setVar('conf_value', 15);
			$configitem_handler->insert($GLOBALS['protectorConfig'][0], true);
		}
	
	
		$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['protector']->getVar('mid')));
		$criteria->add(new Criteria('conf_name', 'union_action'));
		$GLOBALS['protectorConfig'] = $configitem_handler->getObjects($criteria);
		if (isset($GLOBALS['protectorConfig'][0])) {
			$GLOBALS['protectorConfig'][0]->setVar('conf_value', 15);
			$configitem_handler->insert($GLOBALS['protectorConfig'][0], true);
		}
	
	
		$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['protector']->getVar('mid')));
		$criteria->add(new Criteria('conf_name', 'dos_craction'));
		$GLOBALS['protectorConfig'] = $configitem_handler->getObjects($criteria);
		if (isset($GLOBALS['protectorConfig'][0])) {
			$GLOBALS['protectorConfig'][0]->setVar('conf_value', 'bip');
			$configitem_handler->insert($GLOBALS['protectorConfig'][0], true);
		}
	
		$criteria = new CriteriaCompo(new Criteria('conf_modid', $GLOBALS['protector']->getVar('mid')));
		$criteria->add(new Criteria('conf_name', 'stopforumspam_action'));
		$GLOBALS['protectorConfig'] = $configitem_handler->getObjects($criteria);
		if (isset($GLOBALS['protectorConfig'][0])) {
			$GLOBALS['protectorConfig'][0]->setVar('conf_value', 'bip');
			$configitem_handler->insert($GLOBALS['protectorConfig'][0], true);
		}
	}
	
	return true;				
}

?>