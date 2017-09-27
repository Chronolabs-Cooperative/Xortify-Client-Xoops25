<?php
/**
 * @package     xortify
 * @subpackage  module
 * @description	Sector Nexoork Security Drone
 * @author	    Simon Roberts WISHCRAFT <simon@chronolabs.coop>
 * @author	    Richardo Costa TRABIS 
 * @copyright	copyright (c) 2010-2013 XOOPS.org
 * @licence		GPL 2.0 - see docs/LICENCE.txt
 */

defined('XOOPS_ROOT_PATH') or die('Restricted access');

class XortifyUsersPreload extends XoopsPreloadItem
{
	
	static function eventApiServerEnd($args)
	{
		xoops_loadLanguage('modinfo', 'xortify');
		include_once dirname(dirname(__FILE__)) . '/xoops_version.php';
		if (_MI_XOR_MODE!=_MI_XOR_MODE_SERVER)
			return true;
		
		//////error_reporting(0);
		if ($args[1]=='xoops_create_user') {
			
			xoops_load('cache');
			
			xoops_loadLanguage('modinfo', 'xortify');
			$member_handler = xoops_gethandler('member');
			$module_handler = xoops_gethandler('module');
			$config_handler = xoops_gethandler('config');		
			$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
			if (is_object($GLOBALS['xortifyModule'])) {
				$GLOBALS['xortifyModuleConfig'] = $config_handler->getConfigList($GLOBALS['xortifyModule']->getVar('mid'));
			}
			
			$result = $GLOBALS['xoopsCache']->read('user_bounce_last');
			if ((isset($result['when'])?(float)$result['when']:-microtime(true))+$GLOBALS['xortifyModuleConfig']['bounce']<=microtime(true)) {
				$result = array();
				$result['when'] = microtime(true);
				$servers_handler = xoops_getmodulehandler('servers', 'xortify');
				$criteria = new Criteria(true,true);
				$criteria->setSort('RAND()');
				$criteria->setOrder('ASC');
				if ($servers = $servers_handler->getObjects($criteria, true)&&$servers_handler->getCount($criteria)>0) {
					foreach($servers as $sid => $server) {
						$dbserver = parse_url($server->getVar('server'));
						if ($users = $GLOBALS['xoopsCache']->read('server_users_xortify_'.$dbserver['host'])) {
							foreach($users as $uid => $user ) {
						
								$newuser =& $member_handler->createUser();
								$newuser->setVars($user);
								if ($member_handler->insertUser($newuser, true)) {
									$newid = $newuser->getVar('uid');
									@$member_handler->addUserToGroup(XOOPS_GROUP_USERS, $newid);
								}
							}
							$GLOBALS['xoopsCache']->delete('server_users_xortify_'.$dbserver['host']);
						}
					}
				}
				$result['took'] = microtime(true)-$result['when'];
				$GLOBALS['xoopsCache']->write('user_bounce_last', $result, $GLOBALS['xortifyModuleConfig']['bounce']*2);
			}
		}
	}
}

?>