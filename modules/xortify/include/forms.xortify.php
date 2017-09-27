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
 * This File:	forms.xortify.php		
 * Description:	Forms for Xortify Admin and User iNterface
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

	include ('forms.objects.php');
	include ('../class/auth/authfactory.php');
	
	function XortifySignupForm()
	{
	
		$form = new XoopsThemeForm(_XOR_FRM_TITLE, "xortify_member", "", "post");
		
		$form->addElement(new XoopsFormText(_XOR_FRM_UNAME, "uname", 35, 128, (isset($_REQUEST['uname'])?$_REQUEST['uname']:'')));					
		$form->addElement(new XoopsFormPassword(_XOR_FRM_PASS, "pass", 35, 128, (isset($_REQUEST['pass'])?$_REQUEST['pass']:'')), false);					
		$form->addElement(new XoopsFormPassword(_XOR_FRM_VPASS, "vpass", 35, 128, (isset($_REQUEST['vpass'])?$_REQUEST['vpass']:'')), false);					
		$form->addElement(new XoopsFormText(_XOR_FRM_EMAIL, "email", 35, 128, (isset($_REQUEST['email'])?$_REQUEST['email']:'')));											
		$form->addElement(new XoopsFormText(_XOR_FRM_URL, "url", 35, 128, (isset($_REQUEST['url'])?$_REQUEST['url']:'')));											
		$form->addElement(new XoopsFormRadioYN(_XOR_FRM_VIEWEMAIL, "viewemail", (isset($_REQUEST['viewemail'])?$_REQUEST['viewemail']:false)));
		$form->addElement(new XoopsFormSelectTimezone(_XOR_FRM_TIMEZONE, "timezone", (isset($_REQUEST['timezone'])?$_REQUEST['timezone']:'')));
		$xortifyAuth =& XortifyAuthFactory::getAuthConnection(false, $GLOBALS['xoopsModuleConfig']['protocol']);
		$myts =& MyTextSanitizer::getInstance();
		$disclaimer = $xortifyAuth->network_disclaimer();
		if (strlen(trim($disclaimer))==0)
			{
				$disclaimer = _XOR_FRM_NOSOAP_DISCLAIMER;
			}
		$form->addElement(new XoopsFormLabel(_XOR_FRM_DISCLAIMER, $myts->nl2br($disclaimer)));	
		$form->addElement(new XoopsFormRadioYN(_XOR_FRM_DISCLAIMER_AGREE, "agree", false));				
		$form->addElement(new XoopsFormCaptcha(_XOR_FRM_PUZZEL, 'xoopscaptcha', false), true);
		$form->addElement(new XoopsFormHidden('op', 'signup'));	
		$form->addElement(new XoopsFormHidden('fct', 'save'));
		if ($disclaimer != _XOR_FRM_NOSOAP_DISCLAIMER)
			$form->addElement(new XoopsFormButton('', 'submit', _XOR_FRM_REGISTER, 'submit'));	
		return $form->render();
	}
?>