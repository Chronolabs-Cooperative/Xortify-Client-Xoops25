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

class XortifyServersPreload extends XoopsPreloadItem
{
	
	static function eventApiServerEnd($args)
	{
		xoops_loadLanguage('modinfo', 'xortify');
		include_once dirname(dirname(__FILE__)) . '/xoops_version.php';
		if (_MI_XOR_MODE!=_MI_XOR_MODE_SERVER)
			return true;
		

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
		$member_handler = xoops_gethandler('member');
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');		
		$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
		if (is_object($GLOBALS['xortifyModule'])) {
			$GLOBALS['xortifyModuleConfig'] = $config_handler->getConfigList($GLOBALS['xortifyModule']->getVar('mid'));
		}
		
		$result = $GLOBALS['xoopsCache']->read('server_bounce_last');
		if ((isset($result['when'])?(float)$result['when']:-microtime(true))+$GLOBALS['xortifyModuleConfig']['bounce']<=microtime(true)) {
			$result = array();
			$result['when'] = microtime(true);
			$servers_handler = xoops_getmodulehandler('servers', 'xortify');
			$criteria = new Criteria('`online`', true);
			$criteria->setSort('RAND()');
			$criteria->setOrder('ASC');
			if ($servers = $servers_handler->getObjects($criteria, true)&&$servers_handler->getCount($criteria)>0) {
				foreach($servers as $sid => $server) {
					$dbserver = parse_url($server->getVar('server'));
					if ($data = $GLOBALS['xoopsCache']->read('server_bounce_'.$server->getVar('sid'))) {
						$GLOBALS['xortifyModuleConfig']['this_server'] = $data['server']['server'];
						$GLOBALS['xortifyModuleConfig']['this_replace'] = $data['server']['replace'];
						$GLOBALS['xortifyModuleConfig']['this_search'] = $data['server']['search'];
						$GLOBALS['server_level'] = $data['server']['level'];
						foreach($servers_handler->getObjects($criteria, true) as $id => $srv) {
							$GLOBALS['xortifyModuleConfig'][constant('CONF_'.strtoupper($GLOBALS['xortifyModuleConfig']['protocol']))] = str_replace($srv->getVar('replace'), constant('PROT_'.strtoupper($GLOBALS['xortifyModuleConfig']['protocol'])), $srv->getVar('server'));
							$xortifyAuth =& XortifyAuthFactory::getAuthConnection(false, $GLOBALS['xortifyModuleConfig']['protocol']);
							$xortifyAuth->create_user($data['user']['user_viewemail'], $data['user']['uname'], $data['user']['email'], $data['user']['url'], $data['user']['actkey'], 
						 								$data['user']['pass'], $data['user']['timezone_offset'], $data['user']['user_mailok'], $data['siteinfo']);
						}
						$GLOBALS['xoopsCache']->delete('server_bounce_'.$server->getVar('sid'));
						$result['took'] = microtime(true)-$result['when'];
						$GLOBALS['xoopsCache']->write('server_bounce_last', $result, $GLOBALS['xortifyModuleConfig']['bounce']*2);
						return false;
					}
				}
			}
			$result['took'] = microtime(true)-$result['when'];
			$GLOBALS['xoopsCache']->write('server_bounce_last', $result, $GLOBALS['xortifyModuleConfig']['bounce']*2);
		}
	}
}

?>