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
* This File:	log.php
* Description:	Log Object and Handler Class for Xortify
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
class XortifyLog extends XoopsObject
{

    function XortifyLog($id = null)
    {
        $this->initVar('lid', XOBJ_DTYPE_INT, null, false);
		$this->initVar('uid', XOBJ_DTYPE_INT, null, false);
		$this->initVar('uname', XOBJ_DTYPE_TXTBOX, false, false, 64);
		$this->initVar('email', XOBJ_DTYPE_TXTBOX, false, false, 255);
		$this->initVar('ip4', XOBJ_DTYPE_TXTBOX, false, false, 15);
		$this->initVar('ip6', XOBJ_DTYPE_TXTBOX, false, false, 128);
		$this->initVar('proxy-ip4', XOBJ_DTYPE_TXTBOX, false, false, 15);
		$this->initVar('proxy-ip6', XOBJ_DTYPE_TXTBOX, false, false, 128);
		$this->initVar('network-addy', XOBJ_DTYPE_TXTBOX, false, false, 255);
		$this->initVar('provider', XOBJ_DTYPE_TXTBOX, false, false, 128);
		$this->initVar('agent', XOBJ_DTYPE_TXTBOX, false, false, 255);
		$this->initVar('extra', XOBJ_DTYPE_OTHER, false, false);
		$this->initVar('date', XOBJ_DTYPE_INT, null, false);
		$this->initVar('action', XOBJ_DTYPE_ENUM, 'monitored', false, false, false, array('banned', 'blocked', 'monitored'));
    }

    function toArray() {
    	$ret = parent::toArray();
    	$ret['date_datetime'] = date(_DATESTRING, $this->getVar('date'));
    	$ret['action'] = ucfirst($this->getVar('action'));
    	foreach($ret as $key => $value)
    		$ret[str_replace('-', '_', $key)] = $value;
    	return $ret;
    }
    
    function runPrePlugin($default = true) {
		
		include_once($GLOBALS['xoops']->path('/modules/xortify/plugin/'.$this->getVar('provider').'.php'));
		
		switch ($this->getVar('action')) {
			case 'banned':
			case 'blocked':
			case 'monitored':
				$func = ucfirst($this->getVar('action')).'PreHook';
				break;
			default:
				return $default;
				break;
		}
		
		if (function_exists($func))  {
			return @$func($default, $this);
		}
		return $default;
	}
    
	function runPostPlugin($lid) {
		
		include_once($GLOBALS['xoops']->path('/modules/xortify/plugin/'.$this->getVar('provider').'.php'));
		
		switch ($this->getVar('action')) {
			case 'banned':
			case 'blocked':
			case 'monitored':
				$func = ucfirst($this->getVar('action')).'PostHook';
				break;
			default:
				return $lid;
				break;
		}
		
		if (function_exists($func))  {
			return @$func($this, $lid);
		}
		return $lid;
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
class XortifyLogHandler extends XoopsPersistableObjectHandler
{
    function __construct(&$db) 
    {
		$this->db = $db;
        parent::__construct($db, 'xortify_log', 'XortifyLog', "lid", "network-addy");
    }
	
    function insert($object, $force = true) {
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
		
		$criteria = new Criteria('`date`', time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['logdrops'], '<=');
		$this->deleteAll($criteria, true);
		
    	if ($object->isNew()) {
    		$object->setVar('date', time());
    	}
		$run_plugin_action=false;
    	if ($object->vars['action']['changed']==true) {	
			$run_plugin_action=true;
		}
    	if ($run_plugin_action){
    		if ($object->runPrePlugin($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['save_'.$object->getVar('action')])==true)
    			$lid = parent::insert($object, $force);
    		else 
    			return false;
    	} else 	
    		$lid = parent::insert($object, $force);		
    	if ($run_plugin_action)
    		return $object->runPostPlugin($lid);
    	else 	
    		return $lid;
    }
    
    function getCountByField($field, $value) {
    	$criteria = new Criteria('`'.$field.'`', $value);
    	$count = $this->getCount($criteria);
    	return ($count>0?$count:'0');
    }
}

?>