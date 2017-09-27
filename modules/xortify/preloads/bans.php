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

class XortifyBansPreload extends XoopsPreloadItem
{
	
	static function eventApiServerEnd($args)
	{
		xoops_loadLanguage('modinfo', 'xortify');
		include_once dirname(dirname(__FILE__)) . '/xoops_version.php';
		if (_MI_XOR_MODE!=_MI_XOR_MODE_SERVER)
			return true;
		
		//////error_reporting(0);
		if ($args[1]=='ban') {
	
			// Replace Constants
			define("PROT_SOAP", 'soap/');
			define("PROT_JSON", 'json/');
			define("PROT_CURL", 'curl/');
			define("PROT_CURLSERIALISED", 'serial/');
			define("PROT_CURLXML", 'xml/');
			define("PROT_WGETSERIAL", 'serial/');
			define("PROT_WGETXML", 'xml/');
			
			// Config Constants
			define("CONF_SOAP", 'xortify_urisoap');
			define("CONF_JSON", 'xortify_urijson');
			define("CONF_CURL", 'xortify_uricurl');
			define("CONF_CURLSERIALISED", 'xortify_uriserial');
			define("CONF_CURLXML", 'xortify_urixml');
			define("CONF_WGETSERIAL", 'xortify_uriserial');
			define("CONF_WGETXML", 'xortify_urixml');
				
			xoops_load('cache');
			
			xoops_loadLanguage('modinfo', 'xortify');
			$module_handler = xoops_gethandler('module');
			$config_handler = xoops_gethandler('config');		
			$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
			if (is_object($GLOBALS['xortifyModule'])) {
				$GLOBALS['xortifyModuleConfig'] = $config_handler->getConfigList($GLOBALS['xortifyModule']->getVar('mid'));
			}
			
			require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortifyModuleConfig']['protocol'].'.php' );
			$func = strtoupper($GLOBALS['xortifyModuleConfig']['protocol']).'XortifyExchange';
				
			$result = $GLOBALS['xoopsCache']->read('bans_bounce_last');
			if ((isset($result['when'])?(float)$result['when']:-microtime(true))+$GLOBALS['xortifyModuleConfig']['bounce']<=microtime(true)) {
				$result = array();
				$result['when'] = microtime(true);
				$servers_handler = xoops_getmodulehandler('servers', 'xortify');
				$members_handler = xoops_getmodulehandler('members', 'ban');
				$criteria = new Criteria('`member_id`', 0, '<>');
				$criteria->setSort('`made`');
				$criteria->setOrder('DESC');
				if ($members = $members_handler->getObjects($criteria, true)&&$members_handler->getCount($criteria)>0) {
					foreach($members as $member_id => $ban) {
						if ($data = $GLOBALS['xoopsCache']->read('ban_bounce_'.$member_id)) {
							$GLOBALS['ban_level'] = $data['level']+1;
							$criteria = new Criteria('`online`', true);
							$criteria->setSort('RAND()');
							foreach($servers_handler->getObjects($criteria, true) as $id => $srv) {
								$GLOBALS['xortifyModuleConfig'][constant('CONF_'.strtoupper($GLOBALS['xortifyModuleConfig']['protocol']))] = str_replace($srv->getVar('replace'), constant('PROT_'.strtoupper($GLOBALS['xortifyModuleConfig']['protocol'])), $srv->getVar('server'));
								$soapExchg = new $func;							
								$soapExchg->sendBan($data['comment'], $data['category_id'], $data['ip']);
							}
						}
					}
				}
				$result['took'] = microtime(true)-$result['when'];
				$GLOBALS['xoopsCache']->write('bans_bounce_last', $result, $GLOBALS['xortifyModuleConfig']['bounce']*2);
			}
		}
	}
}

?>