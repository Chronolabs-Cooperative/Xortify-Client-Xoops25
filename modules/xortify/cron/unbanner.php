<?php
	include( '../../../mainfile.php' );

	$banmemberhandler =& xoops_getmodulehandler('members','ban');

	$criteria = new CriteriaCompo(new Criteria('`made`', time() - (((7*(24*(60*60))))*3), '<'));
	$criteria->add(new Criteria('`made`', 0, '='), 'OR');
	
	$banned = $banmemberhandler->getObjects($criteria, true);

	$comment_handler = xoops_gethandler('comment');
	$unbanmemberhandler =& xoops_getmodulehandler('members','unban');
	$module_handler = & xoops_gethandler('module');	
	
	$xoBanModule = $module_handler->getByDirname('ban');
	$xoUnbanModule = $module_handler->getByDirname('unban');
	
	if (is_array($banned))
	foreach( $banned as $key => $ban ) {
				
		$unban = $unbanmemberhandler->create();

		$unban->setVars($ban->toArray());
		$unban->setVar('made', time());
	
		$banmemberhandler->delete( $ban, true );
		if ($unbanmemberhandler->insert($unban)) {
			$sql = "UPDATE ".$xoopsDB->prefix('xoopscomments'). " set `com_modid` = '".$xoUnbanModule->getVar('mid')."' WHERE `com_modid` = '".$xoBanModule->getVar('mid')."' AND `com_itemid` = '".$ban->getVar('member_id')."'" ;
			$xoopsDB->queryF($sql);
		}
	} 
	
?>