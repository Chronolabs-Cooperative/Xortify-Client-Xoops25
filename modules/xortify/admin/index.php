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
 * This File:	index.php		
 * Description:	Admin Dashboard and Other panels file
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

	
	include('../../../include/cp_header.php');
	
	////error_reporting(0);
	
	if (!defined('_CHARSET'))
		define ("_CHARSET","UTF-8");
	if (!defined('_CHARSET_ISO'))
		define ("_CHARSET_ISO","ISO-8859-1");
		
	$GLOBALS['myts'] = MyTextSanitizer::getInstance();

	$module_handler = xoops_gethandler('module');
	$config_handler = xoops_gethandler('config');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
	if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid')); 
	
	include_once $GLOBALS['xoops']->path('class'.DS.'cache'.DS.'xoopscache.php');
	include_once $GLOBALS['xoops']->path('class'.DS.'pagenav.php');
	include_once $GLOBALS['xoops']->path('class'.DS.'xoopslists.php');
	include_once $GLOBALS['xoops']->path('class'.DS.'xoopsmailer.php');
	include_once $GLOBALS['xoops']->path('class'.DS.'xoopstree.php');
	include_once $GLOBALS['xoops']->path('class'.DS.'xoopsformloader.php');
	include_once $GLOBALS['xoops']->path('modules'.DS.'xortify'.DS.'class'.DS.'auth'.DS.'authfactory.php');
	include_once $GLOBALS['xoops']->path('modules'.DS.'xortify'.DS.'include'.DS.'functions.php');
	include_once $GLOBALS['xoops']->path('modules'.DS.'xortify'.DS.'include'.DS.'forms.xortify.php');
	
	$GLOBALS['xoopsLoad'] = new XoopsLoad();
	$GLOBALS['xoopsCache'] = new XoopsCache();
	
	xoops_loadLanguage('admin', 'xortify');
	
	if ( file_exists($GLOBALS['xoops']->path('/Frameworks/moduleclasses/moduleadmin/moduleadmin.php'))){
	        include_once $GLOBALS['xoops']->path('/Frameworks/moduleclasses/moduleadmin/moduleadmin.php');
	        //return true;
	    }else{
	        echo xoops_error("Error: You don't use the Frameworks \"admin module\". Please install this Frameworks");
	        //return false;
	    }
	$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['ImageIcon'] = XOOPS_URL .'/'. $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getInfo('icons16');
	$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['ImageAdmin'] = XOOPS_URL .'/'. $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getInfo('icons32');
	
	if ($GLOBALS['xoopsUser']) {
	    $moduleperm_handler =& xoops_gethandler('groupperm');
	    if (!$moduleperm_handler->checkRight('module_admin', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar( 'mid' ), $GLOBALS['xoopsUser']->getGroups())) {
	        redirect_header(XOOPS_URL, 1, _NOPERM);
	        exit();
	    }
	} else {
	    redirect_header(XOOPS_URL . "/user.php", 1, _NOPERM);
	    exit();
	}
	
	xoops_cp_header();
		
	if (!isset($GLOBALS['xoopsTpl']) || !is_object($GLOBALS['xoopsTpl'])) {
		include_once(XOOPS_ROOT_PATH."/class/template.php");
		$GLOBALS['xoopsTpl'] = new XoopsTpl();
	}
	
	$GLOBALS['xoopsTpl']->assign('pathImageIcon', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['ImageIcon']);
	$GLOBALS['xoopsTpl']->assign('pathImageAdmin', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['ImageAdmin']);
				
	$op = isset($_REQUEST['op'])?$_REQUEST['op']:"dashboard";
	$fct = isset($_REQUEST['fct'])?$_REQUEST['fct']:"";
	
	switch($op) {
	case "signup":	
	
		switch ($fct)
		{
		case "save":	

			$xortifyAuth =& XortifyAuthFactory::getAuthConnection(false, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']);
			$myts =& MyTextSanitizer::getInstance();
			$uname = isset($_POST['uname']) ? $myts->stripSlashesGPC(trim($_POST['uname'])) : '';
			$email = isset($_POST['email']) ? $myts->stripSlashesGPC(trim($_POST['email'])) : '';
			$url = isset($_POST['url']) ? $myts->stripSlashesGPC(trim($_POST['url'])) : '';
			$pass = isset($_POST['pass']) ? $myts->stripSlashesGPC(trim($_POST['pass'])) : '';
			$vpass = isset($_POST['vpass']) ? $myts->stripSlashesGPC(trim($_POST['vpass'])) : '';
			$agree = (isset($_POST['agree']) && intval($_POST['agree'])) ? 1 : 0;
			
			if ($agree != 1) {
				$stop .= _US_UNEEDAGREE . '<br />';
			}
			
			$validate = $xortifyAuth->validate($uname, $email, $pass, $vpass);
			
			if ($validate!=false)
				$stop .= "User details didn't validate with Xortify.com<br/>$validate";
			
			$GLOBALS['xoopsLoad']->load("captcha");
			$xoopsCaptcha = XoopsCaptcha::getInstance();
			if (! $xoopsCaptcha->verify() ) {
				$stop .= $xoopsCaptcha->getMessage();
			}
			
			if ($stop!='') {
				xortify_adminMenu(4, 'index.php?op=signup&fct=signup');
				echo "<p align='center' style='font-size: 15px; color: #FF0000;'>$stop</p>";
				$xortifyAuth =& XortifyAuthFactory::getAuthConnection(false, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']);
				$disclaimer = $xortifyAuth->network_disclaimer();
				if (strlen(trim($disclaimer))==0)
				{
					$disclaimer = _XOR_ADMIN_NONETWORKCOMM_DISCLAIMER;
				}
				if ($disclaimer != _XOR_ADMIN_NONETWORKCOMM_DISCLAIMER) {
					$uname = new XoopsFormText('', "uname", 35, 128, (isset($_POST['uname'])?$_POST['uname']:''));
					$pass = new XoopsFormPassword('', "pass", 35, 128, (isset($_POST['pass'])?$_POST['pass']:''));					
					$vpass = new XoopsFormPassword('', "vpass", 35, 128, (isset($_POST['vpass'])?$_POST['vpass']:''));					
					$email = new XoopsFormText('', "email", 35, 128, (isset($_POST['email'])?$_POST['email']:''));											
					$url = new XoopsFormText('', "url", 35, 128, (isset($_POST['url'])?$_POST['url']:''));											
					$viewemail = new XoopsFormRadioYN('', "viewemail", (isset($_POST['viewemail'])?$_POST['viewemail']:false));
					$timezone = new XoopsFormSelectTimezone('', "timezone", (isset($_POST['timezone'])?$_POST['timezone']:''));
					$myts =& MyTextSanitizer::getInstance();
					$disclaim = new XoopsFormLabel('', $myts->nl2br($disclaimer));
					$agree = new XoopsFormRadioYN('', "agree", false);				
					$captcha = new XoopsFormCaptcha('', 'xoopscaptcha', false);
					$op = new XoopsFormHidden('op', 'signup');	
					$fct = new XoopsFormHidden('fct', 'save');
					$submit = new XoopsFormButton('', 'submit', _XOR_FRM_REGISTER, 'submit');
					$GLOBALS['xoopsTpl']->assign('uname',$uname->render());
					$GLOBALS['xoopsTpl']->assign('pass',$pass->render());
					$GLOBALS['xoopsTpl']->assign('vpass',$vpass->render());
					$GLOBALS['xoopsTpl']->assign('email',$email->render());
					$GLOBALS['xoopsTpl']->assign('yoururl',$url->render());
					$GLOBALS['xoopsTpl']->assign('viewemail',$viewemail->render());
					$GLOBALS['xoopsTpl']->assign('timezone',$timezone->render());
					$GLOBALS['xoopsTpl']->assign('disclaimer',$disclaim->render());
					$GLOBALS['xoopsTpl']->assign('agree',$agree->render());
					$GLOBALS['xoopsTpl']->assign('captcha',$captcha->render());
					$GLOBALS['xoopsTpl']->assign('op',$op->render());
					$GLOBALS['xoopsTpl']->assign('fct',$fct->render());
					$GLOBALS['xoopsTpl']->assign('submit',$submit->render());
					$GLOBALS['xoopsTpl']->assign('php_self', $_SERVER['PHP_SELF']);
					$GLOBALS['xoopsTpl']->display($GLOBALS['xoops']->path('/modules/xortify/templates/xortify_cpanel_signup_form.html'));
					xortify_footer_adminMenu();
					xoops_cp_footer();
					exit;
						
				} else {
					$GLOBALS['xoopsTpl']->assign('protocol', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']);
					switch($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']) {
						case 'curlserialised':
						case 'wgetserialised':
							$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_uriserial']);
							break;
						case 'curl':
						case 'json':
							$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urijson']);
							break;
						case 'curlxml':
						case 'wgetxml':
							$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urixml']);
							break;
						case 'soap':
							$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urisoap']);
							break;
					}
					$GLOBALS['xoopsTpl']->assign('error', $disclaimer);
					$GLOBALS['xoopsTpl']->display($GLOBALS['xoops']->path('/modules/xortify/templates/xortify_cpanel_signup_nocommunication.html'));
				}
					
			} else {
				@$xortifyAuth->create_user(	$_REQUEST['viewemail'], $uname, $email, $url, $actkey, 
											$pass, $_REQUEST['timezone'], $_REQUEST['mailok'], $xortifyAuth->check_siteinfo(array()));
				
				$moduleHandler =& xoops_gethandler('module');
				$configHandler =& xoops_gethandler('config');
				if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']))
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $moduleHandler->getByDirname('xortify');
				$configs = $configHandler->getConfigs(new Criteria('conf_modid', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->mid()) );
				foreach($configs as $id => $config)
					switch($config->getVar('conf_name')) {
					case 'xortify_username':
						$config->setVar('conf_value', $uname);
						@$configHandler->insertConfig($config);
						break;
					case 'xortify_password':
						$config->setVar('conf_value', $pass);
						@$configHandler->insertConfig($config);
						break;
					}
				redirect_header("index.php", 4, _XOR_USERCREATED_PLEASEACTIVATE);
				exit(0);
			}
			break;
		default:	
		case "signup":
			xortify_adminMenu(4, 'index.php?op=signup&fct=signup');
			$xortifyAuth =& XortifyAuthFactory::getAuthConnection(false, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']);
			$disclaimer = $xortifyAuth->network_disclaimer();
			if (strlen(trim($disclaimer))==0)
			{
				$disclaimer = _XOR_ADMIN_NONETWORKCOMM_DISCLAIMER;
			}
			if ($disclaimer != _XOR_ADMIN_NONETWORKCOMM_DISCLAIMER) {
				$uname = new XoopsFormText('', "uname", 35, 128, (isset($_POST['uname'])?$_POST['uname']:''));
				$pass = new XoopsFormPassword('', "pass", 35, 128, (isset($_POST['pass'])?$_POST['pass']:''));					
				$vpass = new XoopsFormPassword('', "vpass", 35, 128, (isset($_POST['vpass'])?$_POST['vpass']:''));					
				$email = new XoopsFormText('', "email", 35, 128, (isset($_POST['email'])?$_POST['email']:''));											
				$url = new XoopsFormText('', "url", 35, 128, (isset($_POST['url'])?$_POST['url']:''));											
				$viewemail = new XoopsFormRadioYN('', "viewemail", (isset($_POST['viewemail'])?$_POST['viewemail']:false));
				$timezone = new XoopsFormSelectTimezone('', "timezone", (isset($_POST['timezone'])?$_POST['timezone']:''));
				$myts =& MyTextSanitizer::getInstance();
				$disclaim = new XoopsFormLabel('', $myts->nl2br($disclaimer));
				$agree = new XoopsFormRadioYN('', "agree", false);				
				$captcha = new XoopsFormCaptcha('', 'xoopscaptcha', false);
				$op = new XoopsFormHidden('op', 'signup');	
				$fct = new XoopsFormHidden('fct', 'save');
				$submit = new XoopsFormButton('', 'submit', _XOR_FRM_REGISTER, 'submit');
				$GLOBALS['xoopsTpl']->assign('uname',$uname->render());
				$GLOBALS['xoopsTpl']->assign('pass',$pass->render());
				$GLOBALS['xoopsTpl']->assign('vpass',$vpass->render());
				$GLOBALS['xoopsTpl']->assign('email',$email->render());
				$GLOBALS['xoopsTpl']->assign('yoururl',$url->render());
				$GLOBALS['xoopsTpl']->assign('viewemail',$viewemail->render());
				$GLOBALS['xoopsTpl']->assign('timezone',$timezone->render());
				$GLOBALS['xoopsTpl']->assign('disclaimer',$disclaim->render());
				$GLOBALS['xoopsTpl']->assign('agree',$agree->render());
				$GLOBALS['xoopsTpl']->assign('captcha',$captcha->render());
				$GLOBALS['xoopsTpl']->assign('op',$op->render());
				$GLOBALS['xoopsTpl']->assign('fct',$fct->render());
				$GLOBALS['xoopsTpl']->assign('submit',$submit->render());
				$GLOBALS['xoopsTpl']->assign('php_self', $_SERVER['PHP_SELF']);
				$GLOBALS['xoopsTpl']->display($GLOBALS['xoops']->path('/modules/xortify/templates/xortify_cpanel_signup_form.html'));
				xortify_footer_adminMenu();
				xoops_cp_footer();
				exit;
			} else {
				$GLOBALS['xoopsTpl']->assign('protocol', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']);
				switch($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']) {
					case 'curlserialised':
					case 'wgetserialised':
						$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_uriserial']);
						break;
					case 'curl':
					case 'json':
						$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urijson']);
						break;
					case 'curlxml':
					case 'wgetxml':
						$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urixml']);
						break;
					case 'soap':
						$GLOBALS['xoopsTpl']->assign('port', $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urisoap']);
						break;
				}
				$GLOBALS['xoopsTpl']->assign('error', $disclaimer);
				$GLOBALS['xoopsTpl']->display($GLOBALS['xoops']->path('/modules/xortify/templates/xortify_cpanel_signup_nocommunication.html'));
			}
			break;
		}
		break;
	case "log":	
		
		xortify_adminMenu(3, 'index.php?op=log');
		
		include_once $GLOBALS['xoops']->path( "/class/pagenav.php" );
		
		$log_handler =& xoops_getmodulehandler('log', 'xortify');
			
		$ttl = $log_handler->getCount(NULL);
		$limit = !empty($_REQUEST['limit'])?intval($_REQUEST['limit']):30;
		$start = !empty($_REQUEST['start'])?intval($_REQUEST['start']):0;
		$order = !empty($_REQUEST['order'])?$_REQUEST['order']:'DESC';
		$sort = !empty($_REQUEST['sort'])?''.$_REQUEST['sort'].'':'date';
		
		$pagenav = new XoopsPageNav($ttl, $limit, $start, 'start', 'limit='.$limit.'&sort='.$sort.'&order='.$order.'&op='.$op);
		$GLOBALS['xoopsTpl']->assign('pagenav', $pagenav->renderNav());

		foreach (array(	'action','provider','date','uname','email','ip4','ip6','proxy-ip4',
						'proxy-ip6','network-addy','agent') as $id => $key) {
			$GLOBALS['xoopsTpl']->assign(strtolower(str_replace('-','_',$key).'_th'), '<a href="'.$_SERVER['PHP_SELF'].'?start='.$start.'&limit='.$limit.'&sort='.str_replace('_','-',$key).'&order='.((str_replace('_','-',$key)==$sort)?($order=='DESC'?'ASC':'DESC'):$order).'&op='.$op.'">'.(defined('_XOR_AM_TH_'.strtoupper(str_replace('-','_',$key)))?constant('_XOR_AM_TH_'.strtoupper(str_replace('-','_',$key))):'_XOR_AM_TH_'.strtoupper(str_replace('-','_',$key))).'</a>');
		}
			
		$criteria = new Criteria('1','1');
		$criteria->setStart($start);
		$criteria->setLimit($limit);
		$criteria->setSort('`'.$sort.'`');
		$criteria->setOrder($order);
			
		$logs = $log_handler->getObjects($criteria, true);
		foreach($logs as $id => $log) {
			$GLOBALS['xoopsTpl']->append('log', $log->toArray());
		}
				
		$GLOBALS['xoopsTpl']->display($GLOBALS['xoops']->path('/modules/xortify/templates/xortify_cpanel_log.html'));
		break;		
	case "list":
		
		xortify_adminMenu(2, 'index.php?op=list&fct=bans');
		
		if (!$bans = $GLOBALS['xoopsCache']->read('xortify_bans_cache')) {
			require_once( XOOPS_ROOT_PATH.'/modules/xortify/class/'.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol'].'.php' ); 	
			$func = strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']).'XortifyExchange';
			ob_start();
			$soapExchg = new $func;
			$bans = $soapExchg->retrieveBans();
			ob_end_flush();
			
			$GLOBALS['xoopsCache']->delete('xortify_bans_cache');
			$GLOBALS['xoopsCache']->delete('xortify_bans_cache_backup');			
			$GLOBALS['xoopsCache']->write('xortify_bans_cache', $bans, $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_seconds']);
			$GLOBALS['xoopsCache']->write('xortify_bans_cache_backup', $bans, ($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_seconds'] * 1.45));					
		}
		
		if (!isset($bans['bans'])||$bans['bans']==0) {
			echo _XS_AM_NOCACHEMSG;	
		}	else {
		
			$limit = !empty($_REQUEST['limit'])?intval($_REQUEST['limit']):30;
			$start = !empty($_REQUEST['start'])?intval($_REQUEST['start']):0;
		
			$pagenav = new XoopsPageNav($bans['bans'], $limit, $start, 'start', 'limit='.$limit.'&op='.$op);
			$GLOBALS['xoopsTpl']->assign('pagenav', $pagenav->renderNav());
			$i=0;
			$num=0;
			foreach($bans['data'] as $key => $data) {
				$i++;
				if ($i>=$start&&$num<=$limit) {
					$num++;
					if (strlen($data['ip4'])>0) {
						$ipaddy = $data['ip4'];
						$iptype = _XS_IPTYPE_IP4;
					} elseif (strlen($data['ip6'])>0) {
						$ipaddy = $data['ip6'];
						$iptype = _XS_IPTYPE_IP6;
					} else {
						$ipaddy = '';
						$iptype = _XS_IPTYPE_EMPTY;				
					}

					if (strlen($data['proxy-ip4'])>0) {
						$proxyip = $data['proxy-ip4'];
						$proxyiptype = _XS_IPTYPE_IP4;
					} elseif (strlen($data['proxy-ip6'])>0) {
						$proxyip = $data['proxy-ip6'];
						$proxyiptype = _XS_IPTYPE_IP6;
					} else {
						$proxyip = '';
						$proxyiptype = '';					
					}
				
					$GLOBALS['xoopsTpl']->append('bans', array('netaddy'=>$data['network-addy']?$data['network-addy']:'&nbsp;',
															 'macaddy'=>$data['mac-addy']?$data['mac-addy']:'&nbsp;',
															 'iptype'=>$iptype, 'ipaddy'=>$ipaddy, 
															 'proxyiptype'=>$proxyiptype,'ip'=>$proxyip,
															 'long' => $data['long']?$data['long']:'&nbsp;', 
															 'category' =>$data['category'],'comments'=>(isset($data['comments'])?$data['comments']:array())));
				}		
			}
			$hostname = 'xortify.com';
			switch($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['protocol']) {
				case 'curlserialised':
				case 'wgetserialised':
					$hostname = parse_url($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_uriserial'], PHP_URL_HOST);
					break;
				case 'curl':
				case 'json':
					$hostname = parse_url($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urijson'], PHP_URL_HOST);
					break;
				case 'curlxml':
				case 'wgetxml':
					$hostname = parse_url($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urixml'], PHP_URL_HOST);
					break;
				case 'soap':
					$hostname = parse_url($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_urisoap'], PHP_URL_HOST);
					break;
			}
			$GLOBALS['xoopsTpl']->assign('cloudurl', 'http://'.$hostname);
			$GLOBALS['xoopsTpl']->display($GLOBALS['xoops']->path('/modules/xortify/templates/xortify_cpanel_bans.html'));
		} 
		break;
	case "dashboard":
	default:
		
		echo xortify_adminMenu(1, 'index.php?op=dashboard');
		
	    $log_handler = xoops_getmodulehandler('log', 'xortify');
	
	 	$indexAdmin = new ModuleAdmin();	
		
	    $indexAdmin->addInfoBox(_XOR_ADMIN_COUNTS);
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_BANNED."</label>", $log_handler->getCountByField('action','banned'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_BLOCKED."</label>", $log_handler->getCountByField('action','blocked'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_MONITORED."</label>", $log_handler->getCountByField('action','monitored'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_PROJECTHONEYPOTORG."</label>", $log_handler->getCountByField('provider','projecthoneypot.org'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_PROTECTOR."</label>", $log_handler->getCountByField('provider','protector'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_SPIDERS."</label>", $log_handler->getCountByField('provider','spiders'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_STOPFORUMSPAMCOM."</label>", $log_handler->getCountByField('provider','stopforumspam.com'), 'Green');
	    $indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_XORTIFY."</label>", $log_handler->getCountByField('provider','xortify'), 'Green');

		if ($bans = $GLOBALS['xoopsCache']->read('xortify_bans_cache')) {
			$indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_CLOUDEDBANS."</label>", count($bans['data']), 'Green');
		}
		
		if ($result = $GLOBALS['xoopsCache']->read('xortify_cleanup_last')) {
			$indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_WHENCLEANED."</label>", date(_DATESTRING, $result['when']), 'Purple');
			$indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_CLEANINGTOOK."</label>", $result['took'], 'Purple');
			$indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_FILESDELETED."</label>", $result['files'], 'Purple');
			$indexAdmin->addInfoBoxLine(_XOR_ADMIN_COUNTS, "<label>"._XOR_ADMIN_THEREARE_BYTESSAVED."</label>", $result['size'], 'Purple');
		}	    
		
		$indexAdmin->addInfoBox(_XOR_ADMIN_KEYS);
		$indexAdmin->addInfoBoxLine(_XOR_ADMIN_KEYS, "<label>"._XOR_ADMIN_INSTANCE_KEY."</label>", XORTIFY_INSTANCE_KEY, (constant('XORTIFY_INSTANCE_KEY')!='00000-00000-00000-00000-00000'?'Green':'Red'));
		
	    echo $indexAdmin->renderIndex();	
		
		break;	
	case "about":
		echo xortify_adminMenu(5, 'index.php?op=about');
		$aboutAdmin = new ModuleAdmin();
		$paypalitemno='XORTIFY299';
		$aboutAdmin = new ModuleAdmin();
		$about = $aboutAdmin->renderabout($paypalitemno, false);
		$donationform = array(	0 => '<form name="donation" id="donation" action="http://web.labs.coop/modules/xpayment/" method="post" onsubmit="return xoopsFormValidate_donation();">',
									1 => '<table class="outer" cellspacing="1" width="100%"><tbody><tr><th colspan="2">'.constant('_XOR_AM_ABOUT_MAKEDONATE').'</th></tr><tr align="left" valign="top"><td class="head"><div class="xoops-form-element-caption-required"><span class="caption-text">Donation Amount</span><span class="caption-marker">*</span></div></td><td class="even"><select size="1" name="item[A][amount]" id="item[A][amount]" title="Donation Amount"><option value="5">5.00 AUD</option><option value="10">10.00 AUD</option><option value="20">20.00 AUD</option><option value="40">40.00 AUD</option><option value="60">60.00 AUD</option><option value="80">80.00 AUD</option><option value="90">90.00 AUD</option><option value="100">100.00 AUD</option><option value="200">200.00 AUD</option></select></td></tr><tr align="left" valign="top"><td class="head"></td><td class="even"><input class="formButton" name="submit" id="submit" value="'._SUBMIT.'" title="'._SUBMIT.'" type="submit"></td></tr></tbody></table>',
									2 => '<input name="op" id="op" value="createinvoice" type="hidden"><input name="plugin" id="plugin" value="donations" type="hidden"><input name="donation" id="donation" value="1" type="hidden"><input name="drawfor" id="drawfor" value="Chronolabs Co-Operative" type="hidden"><input name="drawto" id="drawto" value="%s" type="hidden"><input name="drawto_email" id="drawto_email" value="%s" type="hidden"><input name="key" id="key" value="%s" type="hidden"><input name="currency" id="currency" value="AUD" type="hidden"><input name="weight_unit" id="weight_unit" value="kgs" type="hidden"><input name="item[A][cat]" id="item[A][cat]" value="XDN%s" type="hidden"><input name="item[A][name]" id="item[A][name]" value="Donation for %s" type="hidden"><input name="item[A][quantity]" id="item[A][quantity]" value="1" type="hidden"><input name="item[A][shipping]" id="item[A][shipping]" value="0" type="hidden"><input name="item[A][handling]" id="item[A][handling]" value="0" type="hidden"><input name="item[A][weight]" id="item[A][weight]" value="0" type="hidden"><input name="item[A][tax]" id="item[A][tax]" value="0" type="hidden"><input name="return" id="return" value="http://www.chronolabs.com.au/modules/donations/success.php" type="hidden"><input name="cancel" id="cancel" value="http://www.chronolabs.com.au/modules/donations/success.php" type="hidden"></form>',																'D'=>'',
									3 => '',
									4 => '<!-- Start Form Validation JavaScript //-->
	<script type="text/javascript">
	<!--//
	function xoopsFormValidate_donation() { var myform = window.document.donation; 
	var hasSelected = false; var selectBox = myform.item[A][amount];for (i = 0; i < selectBox.options.length; i++ ) { if (selectBox.options[i].selected == true && selectBox.options[i].value != \'\') { hasSelected = true; break; } }if (!hasSelected) { window.alert("Please enter Donation Amount"); selectBox.focus(); return false; }return true;
	}
	//--></script>
	<!-- End Form Validation JavaScript //-->');
		$paypalform = array(	0 => '<form action="https://www.paypal.com/cgi-bin/webscr" method="post">',
								1 => '<input name="cmd" value="_s-xclick" type="hidden">',
								2 => '<input name="hosted_button_id" value="%s" type="hidden">',
								3 => '<img alt="" src="https://www.paypal.com/fr_FR/i/scr/pixel.gif" height="1" border="0" width="1">',
								4 => '<input src="https://www.paypal.com/en_US/i/btn/btn_donate_LG.gif" name="submit" alt="PayPal - The safer, easier way to pay online!" border="0" type="image">',
								5 => '</form>');
		for($key=0;$key<=4;$key++) {
			switch ($key) {
				case 2:
					$donationform[$key] =  sprintf($donationform[$key], $GLOBALS['xoopsConfig']['sitename'] . ' - ' . (strlen($GLOBALS['xoopsUser']->getVar('name'))>0?$GLOBALS['xoopsUser']->getVar('name'). ' ['.$GLOBALS['xoopsUser']->getVar('uname').']':$GLOBALS['xoopsUser']->getVar('uname')), $GLOBALS['xoopsUser']->getVar('email'), XOOPS_LICENSE_KEY, strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('dirname')),  strtoupper($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('dirname')). ' '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('name'));
					break;
			}
		}
			
		$istart = strpos($about, ($paypalform[0]), 1);
		$iend = strpos($about, ($paypalform[5]), $istart+1)+strlen($paypalform[5])-1;
		echo (substr($about, 0, $istart-1));
		echo implode("\n", $donationform);
		echo (substr($about, $iend+1, strlen($about)-$iend-1));
		break;
	}
	
	xortify_footer_adminMenu();
	xoops_cp_footer();
?>