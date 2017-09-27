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

class XortifySfsPreload extends XoopsPreloadItem
{
	
	static function eventApiServerEnd($args)
	{
		xoops_loadLanguage('modinfo', 'xortify');
		include_once dirname(dirname(__FILE__)) . '/xoops_version.php';
		if (_MI_XOR_MODE!=_MI_XOR_MODE_SERVER)
			return true;
		
		//////error_reporting(0);
		if ($args[1]=='checksfsbans') {
			
			if (isset($args[5][$args[1]]['ipdata']))
				$args[5] = $args[5][$args[1]];
			
			
			include_once($GLOBALS['xoops']->path('/modules/xortify/include/functions.php'));
			include_once($GLOBALS['xoops']->path('/modules/xrest/include/common.php'));
								
			xoops_load('xoopscache');
			if (!class_exists('XoopsCache')) {
				// XOOPS 2.4 Compliance
				xoops_load('cache');
				if (!class_exists('XoopsCache')) {
					include_once XOOPS_ROOT_PATH.'/class/cache/xoopscache.php';
				}
			}
			
			
			$checked = $GLOBALS['xoopsCache']->read('xortify_sfs_provider_'.sha1($args[5]['uname'].$args[5]['email'].(isset($args[5]['ip4'])?$args[5]['ip4']:"").(isset($args[5]['ip6'])?$args[5]['ip6']:"").(isset($args[5]['proxy-ip4'])?$args[5]['proxy-ip4']:"").(isset($args[5]['proxy-ip4'])?$args[5]['proxy-ip6']:"").$args[5]['network-addy']));
			
			$module_handler = xoops_gethandler('module');
			$config_handler = xoops_gethandler('config');
			if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module'] = $module_handler->getByDirname('xortify');
			if (!isset($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'])) $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig'] = $config_handler->getConfigList($GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['module']->getVar('mid'));
			
			if (!is_array($checked))
			{
			
				if (is_array($args[6])) {
					if (isset($args[6]['success']))
						if ($args[6]['success']==true)
							if (($args[6]['email']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_freq']||$args[6]['username']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_freq']||$args[6]['ip']['frequency']>=$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_freq']) &&
								(strtotime($args[6]['email']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_lastseen']||strtotime($args[6]['username']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_lastseen']||strtotime($args[6]['ip']['lastseen'])>time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_lastseen'])) {
									
									$GLOBALS['xoopsCache']->write('xortify_sfs_'.sha1($args[5]['uname'].$args[5]['email'].(isset($args[5]['ip4'])?$args[5]['ip4']:"").(isset($args[5]['ip6'])?$args[5]['ip6']:"").(isset($args[5]['proxy-ip4'])?$args[5]['proxy-ip4']:"").(isset($args[5]['proxy-ip4'])?$args[5]['proxy-ip6']:"").$args[5]['network-addy']), array_merge($args[6], array('ipdata' => $args[5])), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);					
									
									xoops_loadLanguage('ban', 'xortify');
									
									$suid = user_uid($args[5]['username'], $args[5]['password']);
									
									$banmemberHandler =& xoops_getmodulehandler('members', 'ban');
									$comment_handler = & xoops_gethandler('comment');
									$module_handler = & xoops_gethandler('module');
									
									$xoModule = $module_handler->getByDirname('ban');
									
									$bans = array(0=>$args[5]['ipdata']);
									$comments = array('comment' => _XOR_BAN_SFS_TYPE."\n".
																  _XOR_BAN_SFS_EMAIL_FREQ.': '.$args[6]['email']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_freq']. "\n".
																  _XOR_BAN_SFS_EMAIL_LASTSEEN.': '.date(_DATESTRING, strtotime($args[6]['email']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_lastseen']) . "\n" .
																  _XOR_BAN_SFS_USERNAME_FREQ.': '.$args[6]['username']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_freq']. "\n".
																  _XOR_BAN_SFS_USERNAME_LASTSEEN.': '.date(_DATESTRING, strtotime($args[6]['username']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_lastseen']) . "\n" .
																  _XOR_BAN_SFS_IP_FREQ.': '.$args[6]['ip']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_freq']. "\n".
																  _XOR_BAN_SFS_IP_LASTSEEN.': '.date(_DATESTRING, strtotime($args[6]['ip']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_lastseen']), 4, $args[5]);
									$error=array();
									
									foreach ($bans as $key => $ban){
										if ($ban['network-addy']=='localhost'  ||
												$ban['ip4']=='127.0.0.1' ||
												strpos($ban['ip6'], '127.0.0.1'))
											$error[] = 'localhost cannot be specified in ban - '.$key;
									
										if ( !(intval($ban['made'])>time()-(48*60*60)  &&
												intval($ban['made'])<time()+(48*60*60)) )
											$error[] = 'ban must be made within '.(48*60*60).' seconds ahead or behind of made server timestamp in ban - '.$key;
									
										$criteria = new CriteriaCompo();
									
										foreach($ban as $field => $value) {
											if ($field!='email'&&preg_match("/^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+([\.][a-z0-9-]+)+$/i", $value))
												$error[] = 'no email specified allowed for field - '.$field.' - in ban - '.$key;
									
											if (strpos(' '.$value, '*'))
												$error[] = 'wildcard * cannot be specified for field - '.$field.' - in ban - '.$key;
									
										}
									
										$criteriaa = new CriteriaCompo(new Criteria('`ip4`', $ban['ip4']));
										$criteriaa->add(new Criteria('`proxy-ip4`', $ban['proxy-ip4']), 'AND');
										$criteriab = new CriteriaCompo(new Criteria('`ip6`', $ban['ip6']));
										$criteriab->add(new Criteria('`proxy-ip6`', $ban['proxy-ip6']), 'AND');
										$criteriac = new CriteriaCompo(new Criteria('`long`', $ban['long']));
										$criteriac->add(new Criteria('`network-addy`', $ban['network-addy']), 'OR');
										$criteria = new CriteriaCompo($criteriaa, 'OR');
										$criteria->add($criteriab, 'OR');
										$criteria->add($criteriac, 'OR');
									
										if ($banmemberHandler->getCount($criteria)>0)
											$error[] = 'Ban already exists for record - '.$criteria->renderWhere();
									}
									
									if (count($error)>0)
										return array("errors" => $error, "made" => time());
									
									foreach ($bans as $key => $ban){
									
										$banning = $banmemberHandler->create();
									
										$banning->setVars($ban, true);
									
										$banning->setVar('suid', $suid);
										$user_handler = xoops_gethandler('user');
										$criteria = new CriteriaCompo(new Criteria('uname', $banning->getVar('uname')));
										$criteria->add(new Criteria('email', $banning->getVar('email')));
										if ($user_handler->getCount($criteria)>0||$banning->getVar('category_id')==1) {
											$banning->setVar('uid', 0);
											$banning->setVar('email', '');
											$banning->setVar('uname', '');
										}
											
										if ($itemid = $banmemberHandler->insert($banning, true)) {
											$ii++;
											if (isset($comments['comment'])) {
												$sql = "INSERT INTO ".$xoopsDB->prefix('xoopscomments'). ' (com_created, com_pid, com_itemid, com_rootid, com_ip, com_title, com_text,  dohtml, dosmiley, doxcode, doimage, dobr, com_icon, com_modid, com_status, com_uid) VALUES("'.time().'", "0", "'.$itemid.'","0","'.$_SERVER['REMOTE_ADDR'].'","Banning Comment :: '.$comments['uname'].' :: '.date('d-M-Y H:i:s').'","'.str_replace('\n', '<br/>', htmlspecialchars($comments['comment'])).'",1,1,1,1,1,1,"'.$xoModule->getVar('mid').'", 2, "'.($suid>0?$suid:0).'")';
												$xoopsDB->queryF($sql);
												$sql = "UPDATE ".$xoopsDB->prefix('users'). 'SET `posts` = `posts` + 1 WHERE uid = '.$suid;
												$xoopsDB->queryF($sql);
													
											} elseif (is_array($comments)) {
												foreach($comments as $cmid => $commentor) {
									
													$sql = "INSERT INTO ".$xoopsDB->prefix('xoopscomments'). ' (com_created, com_pid, com_itemid, com_rootid, com_ip, com_title, com_text,  dohtml, dosmiley, doxcode, doimage, dobr, com_icon, com_modid, com_status, com_uid) VALUES("'.time().'", "0", "'.$itemid.'","0","'.$_SERVER['REMOTE_ADDR'].'","Banning Comment :: '.$commentor['uname'].' :: '.date('d-M-Y H:i:s').'","'.str_replace('\n', '<br/>', htmlspecialchars($commentor['comment'])).'",1,1,1,1,1,1,"'.$xoModule->getVar('mid').'", 2, "'.($suid>0?$suid:0).'")';
													$xoopsDB->queryF($sql);
													$sql = "UPDATE ".$xoopsDB->prefix('users'). 'SET `posts` = `posts` + 1 WHERE uid = '.$suid;
													$xoopsDB->queryF($sql);
												}
											}
											if (!isset($_REQUEST['bounce'])&&intval($_REQUEST['level'])<1) {
												ban_posttosfs("username=".$banning->getVar('uname')."&ip_addr=".$banning->ipaddy()."&email=".$banning->getVar('email')."&api_key="._MI_SERVER_STOPFORUMSPAM_KEY);
											}
											if (!isset($_REQUEST['bounce'])&&intval($GLOBALS['ban_level'])<1) {
												xoops_load('cache');
												$GLOBALS['xoopsCache']->write('ban_bounce_'.$itemid, array('ip'=>$ban['ip4'].$ban['ip6'], 'category_id'=>$ban['category_id'], 'comment'=>$comments[sizeof($comments)-1], 'level'=>isset($GLOBALS['ban_level'])?intval($GLOBALS['ban_level']):0), 3600*2*7*4*6);
											}
												
										}
									}
																	
									$log_handler = xoops_getmodulehandler('log', 'xortify');
									$log = $log_handler->create();
									$log->setVars($args[5]['ipdata']);
									$log->setVar('provider', basename(dirname(__FILE__)));
									$log->setVar('action', 'banned');
									$log->setVar('extra', _XOR_BAN_SFS_TYPE."\n".
														  _XOR_BAN_SFS_EMAIL_FREQ.': '.$args[6]['email']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_freq']. "\n".
														  _XOR_BAN_SFS_EMAIL_LASTSEEN.': '.date(_DATESTRING, strtotime($args[6]['email']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['email_lastseen']) . "\n" .
														  _XOR_BAN_SFS_USERNAME_FREQ.': '.$args[6]['username']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_freq']. "\n".
														  _XOR_BAN_SFS_USERNAME_LASTSEEN.': '.date(_DATESTRING, strtotime($args[6]['username']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['uname_lastseen']) . "\n" .
														  _XOR_BAN_SFS_IP_FREQ.': '.$args[6]['ip']['frequency'].' >= '.$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_freq']. "\n".
														  _XOR_BAN_SFS_IP_LASTSEEN.': '.date(_DATESTRING, strtotime($args[6]['ip']['lastseen'])) . ' > ' . date(_DATESTRING, time()-$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['ip_lastseen']));
									$lid = $log_handler->insert($log, true);
									$GLOBALS['xoopsCache']->write('xortify_core_include_common_end', array('time'=>microtime(true)), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['fault_delay']);
							
								}
					unlinkOldCachefiles('xortify_',$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);
					$GLOBALS['xoopsCache']->write('xortify_sfs_provider_'.sha1($args[5]['uname'].$args[5]['email'].(isset($args[5]['ip4'])?$args[5]['ip4']:"").(isset($args[5]['ip6'])?$args[5]['ip6']:"").(isset($args[5]['proxy-ip4'])?$args[5]['proxy-ip4']:"").(isset($args[5]['proxy-ip4'])?$args[5]['proxy-ip6']:"").$args[5]['network-addy']), array_merge($args[6], array('ipdata' => $args[5])), $GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['moduleConfig']['xortify_ip_cache']);
					$GLOBALS['xortify'][XORTIFY_INSTANCE_KEY][_MI_XOR_VERSION]['_pass'] = true;
						
				}	
			} 
		}
	}
}

?>