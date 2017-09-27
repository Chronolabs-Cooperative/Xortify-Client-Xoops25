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

class XortifyUnbansPreload extends XoopsPreloadItem
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
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');	
		$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
		if (is_object($GLOBALS['xortifyModule'])) {
			$GLOBALS['xortifyModuleConfig'] = $config_handler->getConfigList($GLOBALS['xortifyModule']->getVar('mid'));
		}
		
		require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortifyModuleConfig']['protocol'].'.php' );
		$func = strtoupper($GLOBALS['xortifyModuleConfig']['protocol']).'XortifyExchange';

		$uri = parse_url(XOOPS_URL);
		
		$result = $GLOBALS['xoopsCache']->read('unbans_bounce_last');
		if ((isset($result['when'])?(float)$result['when']:-microtime(true))+$GLOBALS['xortifyModuleConfig']['bounce']*2<=microtime(true)) {
			$result = array();
			$result['when'] = microtime(true);
			$servers_handler = xoops_getmodulehandler('servers', 'xortify');
			$members_handler = xoops_getmodulehandler('members', 'ban');
			$unbanmemberhandler =& xoops_getmodulehandler('members','unban');
			$xoBanModule = $module_handler->getByDirname('ban');
			$xoUnbanModule = $module_handler->getByDirname('unban');	
			$criteria = new Criteria('`member_id`', 0, '<>');
			$criteria->setSort('`made`');
			$criteria->setOrder('DESC');
			if ($members = $members_handler->getObjects($criteria, true)&&$members_handler->getCount($criteria)>0) {
				foreach($members as $member_id => $ban) {
					$criteria = new Criteria('`online`', true);
					$criteria->setSort('RAND()');
					foreach($servers_handler->getObjects($criteria, true) as $id => $srv) {
						$GLOBALS['xortifyModuleConfig'][constant('CONF_'.strtoupper($GLOBALS['xortifyModuleConfig']['protocol']))] = str_replace($srv->getVar('replace'), constant('PROT_'.strtoupper($GLOBALS['xortifyModuleConfig']['protocol'])), $srv->getVar('server'));
						$soapExchg = new $func;							
						$result = $soapExchg->checkUnbanned($ban->ipaddy(), $uri['host']);
						if ($result['unbanned']==true) {
							$unban = $unbanmemberhandler->create();
							$unban->setVars($ban->toArray());
							$unban->setVar('made', time());
							if ($members_handler->delete( $ban, true )) {
								if ($unbanmemberhandler->insert($unban)) {
									$sql = "UPDATE ".$xoopsDB->prefix('xoopscomments'). " set `com_modid` = '".$xoUnbanModule->getVar('mid')."' WHERE `com_modid` = '".$xoBanModule->getVar('mid')."' AND `com_itemid` = '".$ban->getVar('member_id')."'" ;
									$xoopsDB->queryF($sql);
								}
							}
						}
					}
				}
			}
			$result['took'] = microtime(true)-$result['when'];
			$GLOBALS['xoopsCache']->write('unbans_bounce_last', $result, $GLOBALS['xortifyModuleConfig']['bounce']*4);
		}
	}
}

?>