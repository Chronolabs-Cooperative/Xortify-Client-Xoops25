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

class XortifyCorePreload extends XoopsPreloadItem
{
	
	static function eventCoreIncludeCommonStart($args)
	{
		
		//$GLOBALS['xoopsLoad'] = new XoopsLoad();
		$GLOBALS['xoopsCache'] = new XoopsCache();
		// Detect if it is an internal refereer.
		$ip = xortify_getIP();
		if (isset($_SERVER['HTTP_REFERER'])&&$result = $GLOBALS['xoopsCache']->read('xortify_'.strtolower(__FUNCTION__).'_'.md5($ip))) {
			if (strtolower(XOOPS_URL)==strtolower(substr($_SERVER['HTTP_REFERER'], 0, strlen(XOOPS_URL)))&&$result['time']<microtime(true)) {
				$GLOBALS['xoopsCache']->write('xortify_'.strtolower(__FUNCTION__).'_'.md5($ip), array('time'=>microtime(true)+1800), 1800);
				return false;
			}
		}
		$GLOBALS['xoopsCache']->write('xortify_'.strtolower(__FUNCTION__).'_'.md5($ip), array('time'=>microtime(true)+1800), 1800);
		// Runs Security Preloader
		$result = $GLOBALS['xoopsCache']->read('xortify_core_include_common_start');
		if ((isset($result['time'])?(float)$result['time']:0)<=microtime(true)) {
			$GLOBALS['xoopsCache']->write('xortify_core_include_common_start', array('time'=>microtime(true)+600), 600);
			include_once XOOPS_ROOT_PATH . ( '/modules/xortify/include/pre.loader.mainfile.php' );
			$GLOBALS['xoopsCache']->write('xortify_core_include_common_start', array('time'=>microtime(true)), -1);
		}
	}

	static function eventCoreIncludeCommonEnd($args)
	{
		xoops_loadLanguage('modinfo', 'xortify');
		$module_handler = xoops_gethandler('module');
		$config_handler = xoops_gethandler('config');		
		if (!isset($GLOBALS['xortify'])||!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])||!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
		if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])&&is_object($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
			$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
		
		$result = $GLOBALS['xoopsCache']->read('xortify_cleanup_last');
		if ((isset($result['when'])?(float)$result['when']:-microtime(true))+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']<=microtime(true)) {
			$result = array();
			$result['when'] = microtime(true);
			$result['files'] = 0;
			$result['size'] = 0;
			foreach(XortifyCorePreload::getFileListAsArray(XOOPS_VAR_PATH.'/caches/xoops_cache/', 'xortify') as $id => $file) {
				if (file_exists(XOOPS_VAR_PATH.'/caches/xoops_data/'.$file)&&!empty($file)) {
					if (@filectime(XOOPS_VAR_PATH.'/caches/xoops_data/'.$file)<time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']) {
						$result['files']++;
						$result['size'] = $result['size'] + filesize(XOOPS_VAR_PATH.'/caches/xoops_data/'.$file);
						@unlink(XOOPS_VAR_PATH.'/caches/xoops_data/'.$file);
					}
				}
			}
			$result['took'] = microtime(true)-$result['when'];
			$GLOBALS['xoopsCache']->write('xortify_cleanup_last', $result, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']*2);
		}
		
		if (isset($_POST)&&isset($_POST['xortify_check'])) {
			self::doSpamCheck($_POST, 'xortify_check');
		}
		
		if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['lid']))
			if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['lid']==0)
				unset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]);
				
		if (strpos($_SERVER["PHP_SELF"], '/banned.php')>0) {
			return false;
		}
		
		if ((isset($_COOKIE['xortify_lid'])&&$_COOKIE['xortify_lid']!=0)||(isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['lid'])&&$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['lid']!=0)&&!strpos($_SERVER["PHP_SELF"], '/banned.php')) {
			@xortifyDisplayBan();
		} 

		// Detect if it is an internal refereer.
		if (isset($_SERVER['HTTP_REFERER'])&&(isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__]))) {
			if (strtolower(XOOPS_URL)==strtolower(substr($_SERVER['HTTP_REFERER'], 0, strlen(XOOPS_URL)))&&$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__]<microtime(true)) {
				$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__] = microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache'];
				return false;
			}
		}
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__] = microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache'];
		
		// Runs Security Preloader
	    $result = $GLOBALS['xoopsCache']->read('xortify_core_include_common_end');
	    if ((isset($result['time'])?(float)$result['time']:0)<=microtime(true)) {
			$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
			if (XortifyCorePreload::hasAPIUserPass()) {
				include_once XOOPS_ROOT_PATH . ( '/modules/xortify/include/post.loader.mainfile.php' );
			}
			$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
		}
		
		
	}

	static function eventCoreHeaderCacheEnd($args)
	{
		
		// Detect if it is an internal refereer.
		if (isset($_SERVER['HTTP_REFERER'])&&(isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__]))) {
			if (strtolower(XOOPS_URL)==strtolower(substr($_SERVER['HTTP_REFERER'], 0, strlen(XOOPS_URL)))&&$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__]<microtime(true)) {
				$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__] = microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache'];
				return false;
			}
		}
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__] = microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache'];
		// Runs Security Preloader
		include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
		$result = $GLOBALS['xoopsCache']->read('xortify_core_header_cache_end');
		if ((isset($result['time'])?(float)$result['time']:0)<=microtime(true)) {
			$GLOBALS['xoopsCache']->write('xortify_core_header_cache_end', array('time'=>microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
			if (XortifyCorePreload::hasAPIUserPass()) { 		
				include_once XOOPS_ROOT_PATH . ( '/modules/xortify/include/post.header.endcache.php' );
			}
			$GLOBALS['xoopsCache']->write('xortify_core_header_cache_end', array('time'=>microtime(true)), -1);
		}		
		
	}

	static function eventCoreFooterEnd($args)
	{
			// Detect if it is an internal refereer.
		if (isset($_SERVER['HTTP_REFERER'])&&(isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__]))) {
			if (strtolower(XOOPS_URL)==strtolower(substr($_SERVER['HTTP_REFERER'], 0, strlen(XOOPS_URL)))&&$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__]<microtime(true)) {
				$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__] = microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache'];
				return false;
			}
		}
		$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION][__FUNCTION__] = microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache'];
		// Runs Security Preloader
		include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
		$result = $GLOBALS['xoopsCache']->read('xortify_core_footer_end');
		if ((isset($result['time'])?(float)$result['time']:0)<=microtime(true)) {
			$GLOBALS['xoopsCache']->write('xortify_core_footer_end', array('time'=>microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
			if (XortifyCorePreload::hasAPIUserPass()) { 		
				include_once XOOPS_ROOT_PATH . ( '/modules/xortify/include/post.footer.end.php' );
			}
			$GLOBALS['xoopsCache']->write('xortify_core_footer_end', array('time'=>microtime(true)), -1);
		}
		if (isset($_SESSION['xortify']['displayBan']) && strlen($_SESSION['xortify']['displayBan']))
		{
			xoops_loadLanguage('bans', 'xortify');
			echo '<div id="blocker"><div id="mission"><div id="banning" class="window"><div align="center" id="banning-message"><h1 id="banning-header">'._XOR_PAGETITLE.'</h1><div id="banning-slogon">'._XOR_DESCRIPTION.'</div><img src="https://xortify.com/images/logo.png" style="clear:now;" width="313px" /></div></div></div></div>';
		}
	}

	static function eventCoreHeaderAddmeta($args)
	{
		
		if (isset($_SESSION['xortify']['displayBan']) && strlen($_SESSION['xortify']['displayBan']))
		{
			$style = "
				#blocker
				{
					position:					absolute;
					left:						0;
					top:						0;
					z-index:					99998;
					background: 				rgba(11,22,11,0.89);
					min-height: 				101% !important;
					max-width: 					100% !important;
					width: 						100% !important;
					clear:						none;
				}
		
				#mission
				{
					z-index:					99999;
					position:					absolute;
					left:						0;
					top:						0;
					clear:						none;
					min-height: 				101% !important;
					max-width: 					100% !important;
					width: 						100% !important;
				}
		
				#banning
				{
					position:					absolute;
					top: 						89px !important;
					display:					none;
					clear:						none;
					margin-left:				auto;
					margin-right:				auto;
					width:						836px;
					min-height:					256px;
					-webkit-box-shadow: 		-4px 7px 18px rgba(254, 14, 11, 0.87);
					-moz-box-shadow:    		-4px 7px 18px rgba(254, 14, 11, 0.87);
					box-shadow:         		-4px 7px 18px rgba(254, 14, 11, 0.87);
					-webkit-border-radius: 		15px;
					-moz-border-radius: 		15px;
					border-radius: 				15px;\n";
				
			mt_srand(mt_rand(mt_rand(-microtime(true), microtime(true))));
			mt_srand(mt_rand(mt_rand(-microtime(true), microtime(true))));
			mt_srand(mt_rand(mt_rand(-microtime(true), microtime(true))));
		
			$modes = array(	'one'=>array('a'=>'center, ellipse', 'b'=>'radial, center center'),
					'two'=>array('a'=>'-45deg', 'b'=>'left top, right bottom'),
					'three'=>array('a'=>'45deg', 'b'=>'left bottom, right top'),
					'four'=>array('a'=>'top', 'b'=>'left top, left bottom'),
					'five'=>array('a'=>'left', 'b'=>'left top, right top'));
		
			$modeskeys = array('one','two','three','four','five');
		
			$colour = array();
			foreach(array('one', 'two', 'three', 'four') as $key) {
				$colour[$key]['red'] = mt_rand(77, 222);
				$colour[$key]['green'] = mt_rand(88, 177);
				$colour[$key]['blue'] = mt_rand(111, 243);
				if (in_array($key, array('one')))
					$colour[$key]['heat'] = mt_rand(47, 99);
				else
					$colour[$key]['heat'] = mt_rand(37, 99);
				$colour[$key]['opacity'] = (string)round(mt_rand(36, 83) / 93, 2);
			}
			shuffle($modeskeys);
			$state = $modes[$modeskeys[mt_rand(0, count($modekeys)-1)]];
			$style .= '				background:					rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].');
					background:					-moz-linear-gradient('.$state['a'].', rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%, rgba('.$colour['two']['red'].','.$colour['two']['green'].','.$colour['two']['blue'].','.$colour['two']['opacity'].') '.$colour['two']['heat'].'%, rgba('.$colour['three']['red'].','.$colour['three']['green'].','.$colour['three']['blue'].','.$colour['three']['opacity'].') '.$colour['three']['heat'].'%, rgba('.$colour['four']['red'].','.$colour['four']['green'].','.$colour['four']['blue'].','.$colour['four']['opacity'].') '.$colour['four']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%);
					background:					-webkit-gradient('.$state['b'].', color-stop('.$colour['one']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].')), color-stop('.$colour['two']['heat'].'%, rgba('.$colour['two']['red'].','.$colour['two']['green'].','.$colour['two']['blue'].','.$colour['two']['opacity'].')), color-stop('.$colour['three']['heat'].'%, rgba('.$colour['three']['red'].','.$colour['three']['green'].','.$colour['three']['blue'].','.$colour['three']['opacity'].')), color-stop('.$colour['four']['heat'].'%, rgba('.$colour['four']['red'].','.$colour['four']['green'].','.$colour['four']['blue'].','.$colour['four']['opacity'].')), color-stop('.$colour['one']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].')));
					background:					 -webkit-linear-gradient('.$state['a'].', rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%, rgba('.$colour['two']['red'].','.$colour['two']['green'].','.$colour['two']['blue'].','.$colour['two']['opacity'].') '.$colour['two']['heat'].'%, rgba('.$colour['three']['red'].','.$colour['three']['green'].','.$colour['three']['blue'].','.$colour['three']['opacity'].') '.$colour['three']['heat'].'%, rgba('.$colour['four']['red'].','.$colour['four']['green'].','.$colour['four']['blue'].','.$colour['four']['opacity'].') '.$colour['four']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%);										background:					-o-linear-gradient('.$state['a'].', rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%, rgba('.$colour['two']['red'].','.$colour['two']['green'].','.$colour['two']['blue'].','.$colour['two']['opacity'].') '.$colour['two']['heat'].'%, rgba('.$colour['three']['red'].','.$colour['three']['green'].','.$colour['three']['blue'].','.$colour['three']['opacity'].') '.$colour['three']['heat'].'%, rgba('.$colour['four']['red'].','.$colour['four']['green'].','.$colour['four']['blue'].','.$colour['four']['opacity'].') '.$colour['four']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%);
					background:					-ms-linear-gradient('.$state['a'].', rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%, rgba('.$colour['two']['red'].','.$colour['two']['green'].','.$colour['two']['blue'].','.$colour['two']['opacity'].') '.$colour['two']['heat'].'%, rgba('.$colour['three']['red'].','.$colour['three']['green'].','.$colour['three']['blue'].','.$colour['three']['opacity'].') '.$colour['three']['heat'].'%, rgba('.$colour['four']['red'].','.$colour['four']['green'].','.$colour['four']['blue'].','.$colour['four']['opacity'].') '.$colour['four']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%);
					background:					linear-gradient('.$state['a'].', rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%, rgba('.$colour['two']['red'].','.$colour['two']['green'].','.$colour['two']['blue'].','.$colour['two']['opacity'].') '.$colour['two']['heat'].'%, rgba('.$colour['three']['red'].','.$colour['three']['green'].','.$colour['three']['blue'].','.$colour['three']['opacity'].') '.$colour['three']['heat'].'%, rgba('.$colour['four']['red'].','.$colour['four']['green'].','.$colour['four']['blue'].','.$colour['four']['opacity'].') '.$colour['four']['heat'].'%, rgba('.$colour['one']['red'].','.$colour['one']['green'].','.$colour['one']['blue'].','.$colour['one']['opacity'].') '.$colour['one']['heat'].'%);
					filter: progid:DXImageTransform.Microsoft.gradient( startColorstr=\'#ffffff\', endColorstr=\'#ffffff\', GradientType=1 );';
			$style = "		padding: 						13px;
					border: 						9px solid red;
					font-size:						1.478996em;
				}
		
				#banning-close
				{
					font-weight:					bold;
					margin:							5px 3px 5px 0px;
				}
		
				#banning-message
				{
					padding:						11px;
					font-weight:					bold;
				}
		
				#banning-header
				{
					text-align: 					left;
					color: 							#a5ae56;
					text-shadow: 					-2px 5px 8px rgba(9, 14, 011, 0.69);
					text-outline:					3px 2px black;
					-webkit-text-outline:			3px 2px black;
					-moz-text-outline:				3px 2px black;
					margin-left: 					10px;
					font-size: 						1.8699em;
					margin-top: 					35px;
					margin-bottom: 					35px;
					letter-spacing: 				-3px;
					font-weight:					900;
				}
		
				#banning-slogon
				{
					text-align: 					center;
					font-size: 						1.4519669em;
					margin-top: 					5px;
					margin-bottom: 					35px;
					color: 							black;
					text-shadow: 					-2px 4px 6px rgba(9, 29, 91, 0.79);
					text-outline:					2px 2px red;
					-webkit-text-outline:			2px 2px red;
					-moz-text-outline:				2px 2px red;
					padding-left: 					41px;
					padding-right: 					41px;
					line-height: 					0.985699em;
					letter-spacing: 				-2px;
					font-weight:			`		700;
				}
		
				#banning-slogon-red
				{
					color: 							red;
					text-shadow: 					2px 5px 6px rgba(91, 9, 39, 0.99);
					text-outline:					2px 2px black;
					-webkit-text-outline:			2px 2px black;
					-moz-text-outline:				2px 2px black;
					padding-left: 					7px;
					padding-right: 					7px;
					letter-spacing: 				-2px;
					font-weight:					bold;
				}";
			$GLOBALS['xoTheme']->addStylesheet('', array(), $style, 'banningmessage');
		}
		
		/*
		if (isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['_pass'])) {
			if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['_pass'] == true) {
				include_once XOOPS_ROOT_PATH.'/modules/xortify/include/functions.php';
				addmeta_googleanalytics(_XOR_MI_XOOPS_GOOGLE_ANALYTICS_ACCOUNTID_USERPASSED, $_SERVER['HTTP_HOST']);
				if (defined('_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_USERPASSED')&&strlen(constant('_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_USERPASSED'))>=13) { 
					addmeta_googleanalytics(_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_USERPASSED, $_SERVER['HTTP_HOST']);
				}	
			}
		}*/
		
		include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
		$result = $GLOBALS['xoopsCache']->read('xortify_core_header_add_meta');
		if ((isset($result['time'])?(float)$result['time']:0)<=microtime(true)) {
			$GLOBALS['xoopsCache']->write('xortify_core_header_add_meta', array('time'=>microtime(true)+$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
			if (XortifyCorePreload::hasAPIUserPass()) {	
				include_once XOOPS_ROOT_PATH . ( '/modules/xortify/include/post.header.addmeta.php' );
			}
			$GLOBALS['xoopsCache']->write('xortify_core_header_add_meta', array('time'=>microtime(true)), -1);
		}
		
	}
	
	static function hasAPIUserPass()
	{
		
		
		if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_username']!=''&&$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_password']!='')
			return true;
		else
			return false;
	}		
	
	static function getFileListAsArray($dirname, $prefix="xortify")
	{
		
		
		$filelist = array();
		if (substr($dirname, -1) == '/') {
			$dirname = substr($dirname, 0, -1);
		}
		if (is_dir($dirname) && $handle = opendir($dirname)) {
			while (false !== ($file = readdir($handle))) {
				if (!preg_match("/^[\.]{1,2}$/",$file) && is_file($dirname.'/'.$file)) {
					if (!empty($prefix)&&strpos(' '.$file, $prefix)>0) {
						$filelist[$file] = $file;
					} elseif (empty($prefix)) {
						$filelist[$file] = $file;
					}
				}
			}
			closedir($handle);
			asort($filelist);
			reset($filelist);
		}
		return $filelist;
	}
	
	static public function doSpamCheck( $_from = array(), $source = 'xortify_check') {
		if (isset($_from[$source])&&count($_from[$source])>0) {
			require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol'].'.php' );
			$func = strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']).'XortifyExchange';
			$apiExchange = new $func;
			foreach ($_from[$source] as $id => $field) {
				$field = str_replace('[]', '', $field);
				if (is_array($_from[$field])) {
					foreach ($_from[$field] as $id => $data) {
						$result = $apiExchange->checkForSpam($data);
						if ($result['spam']==true) {
							$xortifycookie = unserialize($_COOKIE['xortify']);
							if (isset($xortifycookie['spams']))
								$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams'] = $xortifycookie['xortify']['spams'];
							$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams'] = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams'] + 1;
							unset($_COOKIE['xortify']['spams']);
							setcookie('xortify', serialise(array_merge($xortifycookie,array('spams' => $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams']))), time()+3600*24*7*4*3);
							xoops_loadLanguage('ban', 'xortify');
							if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['spams_allowed']) {
									
								$results[] = $apiExchange->sendBan(array('comment'=>_XOR_SPAM . ' :: [' . $data . '] len('.strlen($data).')'), 2, xortify_getIPData());
									
								$log_handler = xoops_getmodulehandler('log', 'xortify');
								$log = $log_handler->create();
								$log->setVars(xortify_getIPData($ip));
								$log->setVar('provider', basename(dirname(__FILE__)));
								$log->setVar('action', 'banned');
								$log->setVar('extra', _XOR_SPAM . ' :: [' . $data . '] len('.strlen($data).')');
								$log->setVar('agent', $_SERVER['HTTP_USER_AGENT']);
								if (isset($GLOBALS['xoopsUser'])) {
									$log->setVar('email', $GLOBALS['xoopsUser']->getVar('email'));
									$log->setVar('uname', $GLOBALS['xoopsUser']->getVar('uname'));
								}
		
								$lid = $log_handler->insert($log, true);
								$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
								$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
								setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
								@xortifyDisplayBan();
							} else {
								$log_handler = xoops_getmodulehandler('log', 'xortify');
								$log = $log_handler->create();
								$log->setVars($ipdata);
								$log->setVar('provider', basename(dirname(__FILE__)));
								$log->setVar('action', 'blocked');
								$log->setVar('extra', _XOR_SPAM . ' :: [' . $_REQUEST[$field] . '] len('.strlen($_REQUEST[$field]).')');
								if (isset($GLOBALS['xoopsUser'])) {
									$log->setVar('email', $GLOBALS['xoopsUser']->getVar('email'));
									$log->setVar('uname', $GLOBALS['xoopsUser']->getVar('uname'));
								}
								$lid = $log_handler->insert($log, true);
									
		
								xoops_loadLanguage('ban', 'xortify');
		
								$module_handler = xoops_gethandler('module');
								$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
		
								$xoopsOption['template_main'] = 'xortify_spamming_notice.html';
								include_once XOOPS_ROOT_PATH.'/header.php';
									
								addmeta_googleanalytics(_XOR_MI_XOOPS_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS, $_SERVER['HTTP_HOST']);
								if (defined('_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS')&&strlen(constant('_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS'))>=13) {
									addmeta_googleanalytics(_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS, $_SERVER['HTTP_HOST']);
								}
		
								$GLOBALS['xoopsTpl']->assign('xoops_pagetitle', _XOR_SPAM_PAGETITLE);
								$GLOBALS['xoopsTpl']->assign('description', _XOR_SPAM_DESCRIPTION);
								$GLOBALS['xoopsTpl']->assign('version', $GLOBALS['xortifyModule']->getVar('version')/100);
								$GLOBALS['xoopsTpl']->assign('platform', XOOPS_VERSION);
								$GLOBALS['xoopsTpl']->assign('provider', basename(dirname(__FILE__)));
								$GLOBALS['xoopsTpl']->assign('spam', htmlspecialchars($data));
								$GLOBALS['xoopsTpl']->assign('agent', $_SERVER['HTTP_USER_AGENT']);
		
								$GLOBALS['xoopsTpl']->assign('xoops_lblocks', false);
								$GLOBALS['xoopsTpl']->assign('xoops_rblocks', false);
								$GLOBALS['xoopsTpl']->assign('xoops_ccblocks', false);
								$GLOBALS['xoopsTpl']->assign('xoops_clblocks', false);
								$GLOBALS['xoopsTpl']->assign('xoops_crblocks', false);
								$GLOBALS['xoopsTpl']->assign('xoops_showlblock', false);
								$GLOBALS['xoopsTpl']->assign('xoops_showrblock', false);
								$GLOBALS['xoopsTpl']->assign('xoops_showcblock', false);
		
								include_once XOOPS_ROOT_PATH.'/footer.php';
							}
							exit(0);
						}
					}
				} else {
					$result = $apiExchange->checkForSpam($_from[$field], is_group(user_groups(), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['allow_adult']));
					if ($result['spam']==true) {
							
						$xortifycookie = unserialize($_COOKIE['xortify']);
						if (isset($xortifycookie['spams']))
							$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams'] = $xortifycookie['xortify']['spams'];
						$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams'] = $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams'] + 1;
						unset($_COOKIE['xortify']['spams']);
						setcookie('xortify', serialise(array_merge($_COOKIE['xortify'],array('spams' => $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams']))), time()+3600*24*7*4*3);
		
						xoops_loadLanguage('ban', 'xortify');
						print_r($GLOBALS['xortify']);
						exit(0);
							
						xoops_loadLanguage('ban', 'xortify');
							
						if ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['spams']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['spams_allowed']) {
								
							$results[] = $apiExchange->sendBan(array('comment'=>_XOR_SPAM . ' :: [' . $_REQUEST[$field] . '] len('.strlen($_REQUEST[$field]).')'), 2, xortify_getIPData());
								
							$log_handler = xoops_getmodulehandler('log', 'xortify');
							$log = $log_handler->create();
							$log->setVars(xortify_getIPData($ip));
							$log->setVar('provider', basename(dirname(__FILE__)));
							$log->setVar('action', 'banned');
							$log->setVar('extra', _XOR_SPAM . ' :: [' . $_REQUEST[$field] . '] len('.strlen($_REQUEST[$field]).')');
							$log->setVar('agent', $_SERVER['HTTP_USER_AGENT']);
							if (isset($GLOBALS['xoopsUser'])) {
								$log->setVar('email', $GLOBALS['xoopsUser']->getVar('email'));
								$log->setVar('uname', $GLOBALS['xoopsUser']->getVar('uname'));
							}
		
							$lid = $log_handler->insert($log, true);
							$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
							$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY]['lid'] = $lid;
							setcookie('xortify_lid', $lid, time()+3600*24*7*4*3);
							@xortifyDisplayBan();
		
						} else {
							$log_handler = xoops_getmodulehandler('log', 'xortify');
							$log = $log_handler->create();
							$log->setVars($ipdata);
							$log->setVar('provider', basename(dirname(__FILE__)));
							$log->setVar('action', 'blocked');
							$log->setVar('extra', _XOR_SPAM . ' :: [' . $_REQUEST[$field] . '] len('.strlen($_REQUEST[$field]).')');
							if (isset($GLOBALS['xoopsUser'])) {
								$log->setVar('email', $GLOBALS['xoopsUser']->getVar('email'));
								$log->setVar('uname', $GLOBALS['xoopsUser']->getVar('uname'));
							}
							$lid = $log_handler->insert($log, true);
		
							$module_handler = xoops_gethandler('module');
							$GLOBALS['xortifyModule'] = $module_handler->getByDirname('xortify');
		
							$xoopsOption['template_main'] = 'xortify_spamming_notice.html';
							include_once XOOPS_ROOT_PATH.'/header.php';
		
							addmeta_googleanalytics(_XOR_MI_XOOPS_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS, $_SERVER['HTTP_HOST']);
							if (defined('_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS')&&strlen(constant('_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS'))>=13) {
								addmeta_googleanalytics(_XOR_MI_CLIENT_GOOGLE_ANALYTICS_ACCOUNTID_FAILEDTOPASS, $_SERVER['HTTP_HOST']);
							}
		
							$GLOBALS['xoopsTpl']->assign('xoops_pagetitle', _XOR_SPAM_PAGETITLE);
							$GLOBALS['xoopsTpl']->assign('description', _XOR_SPAM_DESCRIPTION);
							$GLOBALS['xoopsTpl']->assign('version', $GLOBALS['xortifyModule']->getVar('version')/100);
							$GLOBALS['xoopsTpl']->assign('platform', XOOPS_VERSION);
							$GLOBALS['xoopsTpl']->assign('provider', basename(dirname(__FILE__)));
							$GLOBALS['xoopsTpl']->assign('spam', htmlspecialchars($_REQUEST[$field]));
							$GLOBALS['xoopsTpl']->assign('agent', $_SERVER['HTTP_USER_AGENT']);
		
							$GLOBALS['xoopsTpl']->assign('xoops_lblocks', false);
							$GLOBALS['xoopsTpl']->assign('xoops_rblocks', false);
							$GLOBALS['xoopsTpl']->assign('xoops_ccblocks', false);
							$GLOBALS['xoopsTpl']->assign('xoops_clblocks', false);
							$GLOBALS['xoopsTpl']->assign('xoops_crblocks', false);
							$GLOBALS['xoopsTpl']->assign('xoops_showlblock', false);
							$GLOBALS['xoopsTpl']->assign('xoops_showrblock', false);
							$GLOBALS['xoopsTpl']->assign('xoops_showcblock', false);
		
							include_once XOOPS_ROOT_PATH.'/footer.php';
						}
						exit(0);
					}
				}
			}
		}
	}

}

?>