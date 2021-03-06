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
 * This File:	xortify.php		
 * Description:	Xortify plugin file called by /class/log.php
 * Date:		06-Jan-2015 03:45 AEST
 * License:		GNU3
 * 
 */
	function BannedPreHook($default, $log) {
		return $default;
	}
	
	function BlockedPreHook($default, $log) {
		return $default;
	}

	function MonitoredPreHook($default, $log) {
		return $default;
	}
	
	function BannedPostHook($log, $lid) {
		return $lid;
	}
	
	function BlockedPostHook($log, $lid) {
		return $lid;
	}

	function MonitoredPostHook($log, $lid) {
		return $lid;
	}
	
?>