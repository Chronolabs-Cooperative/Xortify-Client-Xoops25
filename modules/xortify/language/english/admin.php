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
 * This File:	admin.php		
 * Description:	Admin language defines.
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */

	// Version 1.17
	define('_XS_IPTYPE_IP4', 'IPv4');
	define('_XS_IPTYPE_IP6', 'IPv6');	
	define('_XS_IPTYPE_EMPTY', 'No IP');
	define('_XS_AM_IPTYPE', 'IP Type');
	define('_XS_AM_IPADDRESS', 'IP Address');	
	define('_XS_AM_NETADDRESS', 'Network Address');
	define('_XS_AM_PROXYIP', 'Proxy IP');	
	define('_XS_AM_MACADDRESS', 'Mac Address');
	define('_XS_AM_LONG', 'Network Pointer');	
	
	define('_XS_AM_BANS', 'Current Network Bans');	
	
	define('_XS_AM_NOCACHEMSG', '<center><font size="+2">EMPTY BAN CACHE!! NOTHING TO DISPLAY!!</font></center>');

	// Version 2.40
	define('_XOR_AM_LOG_H1', 'Xortify Usage Log');
	define('_XOR_AM_LOG_P', 'This is the actions that have occured on your system in the last period up unto the log drop date!');
	define('_XOR_AM_TH_ACTION', 'Action');
	define('_XOR_AM_TH_PROVIDER', 'Provider');
	define('_XOR_AM_TH_DATE', 'Date');
	define('_XOR_AM_TH_UNAME', 'Username');
	define('_XOR_AM_TH_EMAIL', 'Email');
	define('_XOR_AM_TH_IP4', 'Ip4');
	define('_XOR_AM_TH_IP6', 'IP6');
	define('_XOR_AM_TH_PROXY_IP4', 'Proxy IP4');
	define('_XOR_AM_TH_PROXY_IP6', 'Proxy IP6');
	define('_XOR_AM_TH_NETWORK_ADDY', 'Netbios Address');
	define('_XOR_AM_TH_AGENT', 'User Agent');
	
	// Version 2.56
	define('_XOR_ADMIN_COUNTS', 'Log Action and Counts');
	define('_XOR_ADMIN_THEREARE_BANNED', 'Banned Individuals:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_BLOCKED', 'Blocked Individuals:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_MONITORED', 'Monitored Individuals:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_PROJECTHONEYPOTORG', 'Individuals or bots picked up by ProjectHoneypot.org:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_PROTECTOR', 'Individuals or bots picked up by Protector Module:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_SPIDERS', 'Individuals or bots picked up by Spiders Module:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_STOPFORUMSPAMCOM', 'Individuals or bots picked up by StopForumSpam.com:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_XORTIFY', 'Individuals or bots picked up by Xortify Cloud:&nbsp;%s');
	define('_XOR_ADMIN_THEREARE_CLOUDEDBANS', 'Clouded Bans Loaded from Xortify Cloud:&nbsp;%s');
	
	//Version 2.59
	//About
	define('_XOR_ADMIN_ABOUT_MAKEDONATE', 'Make donation to Chronolabs co-op');
	
	//Version 2.99.1
	define('_XOR_ADMIN_MAKEDONATE', 'Make Donation to Further Xortify!');
	define('_XOR_ADMIN_NONETWORKCOMM_DISCLAIMER', 'The current URI is unaccessable on the selected protocol. This could mean you are either missing a required PHP Extension or have a firewall blocking port 80 to the Xortify Cloud.<br/><br/><strong>You can try changing the protocol selected in preferences to see if this may elivate the communication fawl of your hosting services.</strong>');
	define('_XOR_ADMIN_ERROR_OCCURED', 'Error Occured Communicating with cloud');
	define('_XOR_ADMIN_ERROR_URL', 'URL/URI Being Contacted');
	define('_XOR_ADMIN_ERROR_PROTOCOL', 'Protocol Being Used');
	define('_XOR_ADMIN_SIGNUP_XORTIFY_H2', 'Signup to the XOOPS fortification cloud');
	define('_XOR_ADMIN_SIGNUP_XORTIFY_P', 'Here you can signup to the XOOPS fortification cloud called Xortify, the main node for this cloud is featured at http://xortify.com but there can be other nodes, this will prevent spam signup, website harvesting, and general hacking of your site.<br/><br/>It will also share the IP\'s of Bad IP Highlighted by Protector with other people running Xortify.');
	define('_XOR_ADMIN_SIGNUP_XORTIFY_FORM_TD2', 'Sign-up this Website\'s User Account on the Xortify Cloud.');
	
	//Version 3.0
	define('_XOR_AM_ABOUT_MAKEDONATE', 'Make Xortify Better, Donate Now!!');
	
	//Version 3.01
	define('_XOR_ADMIN_THEREARE_WHENCLEANED', 'Xortify File Cache Cleaned Last: %s');
	define('_XOR_ADMIN_THEREARE_CLEANINGTOOK', 'Xortify File Cache Cleaning Took: %s seconds');
	define('_XOR_ADMIN_THEREARE_FILESDELETED', 'Xortify Cache Files Deleted: %s');
	define('_XOR_ADMIN_THEREARE_BYTESSAVED', 'Xortify Cache Cleaning Saved: %s bytes');
	define('_XS_AM_CATEGORY', 'Ban Category');
	define('_XS_AM_BANID', 'Ban Id:');
	
	// Version 4.99.1
	define('_XOR_ADMIN_KEYS', 'System Keys');
	define('_XOR_ADMIN_INSTANCE_KEY', 'Xortify Local Instance Key: %s');
?>