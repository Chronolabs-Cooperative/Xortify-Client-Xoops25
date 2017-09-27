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

class XortifyUnbannerPreload extends XoopsPreloadItem
{
	
	static function eventApiServerEnd($args)
	{
		xoops_loadLanguage('modinfo', 'xortify');
		include_once dirname(dirname(__FILE__)) . '/xoops_version.php';
		if (_MI_XOR_MODE!=_MI_XOR_MODE_SERVER)
			return true;
		

		
		xoops_load('cache');
		
		xoops_loadLanguage('modinfo', 'xortify');
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');		
		$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
		if (is_object($GLOBALS['xortifyModule'])) {
			$GLOBALS['xortifyModuleConfig'] = $config_handler->getConfigList($GLOBALS['xortifyModule']->getVar('mid'));
		}
		
		$result = $GLOBALS['xoopsCache']->read('unbanner_bounce_last');
		if ((isset($result['when'])?(float)$result['when']:-microtime(true))+$GLOBALS['xortifyModuleConfig']['bounce']<=microtime(true)) {
			$result = array();
			$result['when'] = microtime(true);
			ob_start();
			include_once($GLOBALS['xoops']->path('/modules/xortify/cron/unbanner.php'));
			ob_end_clean();
			$result['took'] = microtime(true)-$result['when'];
			$GLOBALS['xoopsCache']->write('unbanner_bounce_last', $result, $GLOBALS['xortifyModuleConfig']['bounce']*2);
		}
	}
}

?>