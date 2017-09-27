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
 * This File:	emails.php
 * Description:	Emails Registrar in Xortify Cloud
 * Date:		30/03/2012 19:34 AEST
 * License:		GNU3
 *
 * Table:
 * 
 * 		CREATE TABLE `xortify_emails` (
 * 		 `eid` mediumint(32) unsigned NOT NULL AUTO_INCREMENT,
 * 		 `email` varchar(255) NOT NULL DEFAULT '',
 * 		 `uid` int(13) NOT NULL DEFAULT '0',
 * 		 `count` int(26) NOT NULL DEFAULT '1',
 * 		 `encounter` int(13) NOT NULL DEFAULT '0',
 * 		PRIMARY KEY (`eid`)
 * 		) ENGINE=INNODB DEFAULT CHARSET=utf8;
 *
 */

if (!defined('XOOPS_ROOT_PATH')) {
	exit();
}

xoops_load('XoopsUserUtility');

/**
 * Class for Blue Room Xortify Email
 * @author Simon Roberts <simon@xoops.org>
 * @copyright copyright (c) 2009-2003 XOOPS.org
 * @package xortify
 */
class XortifyEmails extends XoopsObject
{
	var $_ip = '127.0.0.1';

    function XortifyEmails($id = null)
    {
        $this->initVar('eid', XOBJ_DTYPE_INT, null, false);
		$this->initVar('email', XOBJ_DTYPE_TXTBOX, false, true, 255);
		$this->initVar('uid', XOBJ_DTYPE_INT, true, false);
		$this->initVar('count', XOBJ_DTYPE_INT, true, false);
		$this->initVar('encounter', XOBJ_DTYPE_INT, time(), false);
   }

    function toArray() {
    	$ret = parent::toArray();
    	$ret['encounter_datetime'] = date(_DATESTRING, $this->getVar('encounter'));
    	foreach($ret as $key => $value)
    		$ret[str_replace('-', '_', $key)] = $value;
    	return $ret;
    }
    
}


/**
* XOOPS Xortify Email handler class.
* This class is responsible for providing data access mechanisms to the data source
* of XOOPS user class objects.
*
* @author  Simon Roberts <simon@chronolabs.coop>
* @package xortify
*/
class XortifyEmailsHandler extends XoopsPersistableObjectHandler
{
    function __construct(&$db) 
    {
		$this->db = $db;
        parent::__construct($db, 'xortify_emails', 'XortifyEmails', "eid", "email");
    }
    
    function insert($object, $force = true) {
    	if ($this->getCount(new criteria('email', $object->getVar('email')))>0) {
    		$objects = $this->getObjects(new criteria('email', $object->getVar('email')), false);
    		$ip = $object->_ip;
    		if (isset($objects[0]))
    			$object = $objects[0];
    		$object->_ip = $ip;
    	}
    	$object->setVar('count', $object->getVar('count')+1);
    	$object->setVar('encounter', time());
    	if (isset($GLOBALS['xoopsUser'])) {
    		if ($object->getVar('uid')==0)
    			$object->setVar('uid', $GLOBALS['xoopsUser']->getVar('uid'));
    		$email_links_handlers = xoops_getmodulehandler('emails_links', 'xortify');
    		$links = $email_links_handlers->create(true);
    		$links->setVar('ip', ( !isset($object->_ip) || empty($object->_ip) ? XoopsUserUtility::getIP(true) : $object->_ip));
    		$links->setVar('uid', $GLOBALS['xoopsUser']->getVar('uid'));
    		$links->setVar('eid', $id = parent::insert($object, $force));
    		$email_links_handlers->insert($links, $force);
    	} else {
    		$id = parent::insert($object, $force);
    	}
    	return $id;
    }
}

?>