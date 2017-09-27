<?php
/**
 * @package     xortify
 * @subpackage  module
 * @description	Sector Network Security Drone
 * @author	    Simon Roberts WISHCRAFT <simon@chronolabs.coop>
 * @copyright	copyright (c) 2010-2013 XOOPS.org
 * @licence		GPL 2.0 - see docs/LICENCE.txt
 */
			
	define('_XOR_PAGETITLE', 'You are Banned!!');
	define('_XOR_DESCRIPTION', 'You have been Banned from our site by Xortify, this is possibly done by one of our third parties like Stop Forum Spam or Project Honeypot, you will have to check the provider of the ban!<br/><br/>IP Bans that is a ban that is based on the provider "Xortify" are with your IP Can be removed by going to <a href="https://xortify.com/modules/unban/">XORTIFY DOT COM</a><br/><br/>This ban is not permenant and will drop in 3 months!');
	
	// Version 2.40
	define('_XOR_BAN_PHP_TYPE','Project Honey Pot Ban - Details:');
	define('_XOR_BAN_PHP_OCTETA','Number of Days');
	define('_XOR_BAN_PHP_OCTETB','Severity');
	define('_XOR_BAN_PHP_OCTETC','Scan Mode');
	define('_XOR_BAN_SPIDER_TYPE','Spider Block - $_POST Variables are:');
	define('_XOR_BAN_SFS_TYPE','Stop Forum Spam Ban - Details:');
	define('_XOR_BAN_SFS_EMAIL_FREQ','Email Frequency');
	define('_XOR_BAN_SFS_EMAIL_LASTSEEN','Email Last Seen');
	define('_XOR_BAN_SFS_USERNAME_FREQ','Usename Frequency');
	define('_XOR_BAN_SFS_USERNAME_LASTSEEN','Username Last Seen');
	define('_XOR_BAN_SFS_IP_FREQ','IP Frequency');
	define('_XOR_BAN_SFS_IP_LASTSEEN','IP Last Seen');
	
	// Version 2.44
	define('_XOR_BAN_XORT_KEY', 'Field');
	define('_XOR_BAN_XORT_MATCH', 'Match');
	define('_XOR_BAN_XORT_LENGTH', 'Length');
	
	// Version 4.06
	define('_XOR_WORDS', 'Minimum Word Criteria');
	define('_XOR_SPAM', 'Spam Heuristics');
	define('_XOR_WORDS_PAGETITLE', 'Minimum Word Criteria not met!');
	define('_XOR_SPAM_PAGETITLE', 'Spam Heuristics Flagged!');
	define('_XOR_WORDS_DESCRIPTION', '<p align="center"><img align="middle" src="'.XOOPS_URL.'/modules/xortify/images/accessdenied.png"></p><p align="center" style="font-size:18px">You have been blocked from our site by Xortify, this is because you didn\'t meet the minimum word requirements for a submissions; you cannot be banned for this you will have to press the back button and try again!</p>');
	define('_XOR_SPAM_DESCRIPTION', '<p align="center"><img align="middle" src="'.XOOPS_URL.'/modules/xortify/images/accessdenied.png"></p><p align="center" style="font-size:18px">You have been blocked for submitted spam by our spam heuristic checking system Xortify, this is possibly done by one of our third parties like Stop Forum Spam or Project Honeypot, you will have to check the provider of the ban!</p><div style="clear:both; height: 25px;">&nbsp;</div><p align="center" style="font-size:14px">You can occur an IP Bans in a certain number of these; that is a ban that is based on the provider "Xortify" are with your IP Can be removed by going to <a href="http://xortify.com/modules/unban/">XORTIFY DOT COM</a><br/><br/>This ban is not permenant and will drop in 3 months!</p>');
?>