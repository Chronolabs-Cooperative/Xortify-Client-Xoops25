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
* This File:	server.php
* Description:	Server Object and Handler Class for Xortify
* Date:			06-Jan-2015 03:45 AEST
* License:		GNU3
*
*/



if (!defined('XOOPS_ROOT_PATH')) {
	exit();
}
/**
 * Class for Blue Room Xortify Log
 * @author Simon Roberts <simon@xoops.org>
 * @copyright copyright (c) 2009-2003 XOOPS.org
 * @package kernel
 */
class XortifyServers extends XoopsObject
{

    function XortifyServers($id = null)
    {
        $this->initVar('sid', XOBJ_DTYPE_INT, null, false);
		$this->initVar('server', XOBJ_DTYPE_TXTBOX, false, true, 255);
		$this->initVar('replace', XOBJ_DTYPE_TXTBOX, false, true, 255);
		$this->initVar('search', XOBJ_DTYPE_TXTBOX, false, true, 64);
		$this->initVar('online', XOBJ_DTYPE_INT, true, false);
		$this->initVar('polled', XOBJ_DTYPE_INT, time(), false);
		$this->initVar('user', XOBJ_DTYPE_TXTBOX, false, false, 64);
		$this->initVar('pass', XOBJ_DTYPE_TXTBOX, false, false, 32);
   }

    function toArray() {
    	$ret = parent::toArray();
    	$ret['polled_datetime'] = date(_DATESTRING, $this->getVar('polled'));
    	$ret['online'] = ($this->getVar('online')==true?_YES:_NO);
    	$ret['level'] = 0;
    	unset($ret['user']);
    	unset($ret['pass']);
    	foreach($ret as $key => $value)
    		$ret[str_replace('-', '_', $key)] = $value;
    	return $ret;
    }
    
}


/**
* XOOPS Xortify Log handler class.
* This class is responsible for providing data access mechanisms to the data source
* of XOOPS user class objects.
*
* @author  Simon Roberts <simon@chronolabs.coop>
* @package kernel
*/
class XortifyServersHandler extends XoopsPersistableObjectHandler
{
    function __construct(&$db) 
    {
		$this->db = $db;
        parent::__construct($db, 'xortify_servers', 'XortifyServers', "sid", "server");
    }
}

?>