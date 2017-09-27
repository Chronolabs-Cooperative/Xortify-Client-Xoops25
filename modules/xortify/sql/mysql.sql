CREATE TABLE `xortify_log` (
  `lid` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `uid` mediumint(8) unsigned NOT NULL DEFAULT '0',
  `uname` varchar(64) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `ip4` varchar(15) NOT NULL DEFAULT '0.0.0.0',
  `ip6` varchar(128) NOT NULL DEFAULT '0:0:0:0:0:0',
  `proxy-ip4` varchar(64) NOT NULL DEFAULT '0.0.0.0',
  `proxy-ip6` varchar(128) NOT NULL DEFAULT '0:0:0:0:0:0',
  `network-addy` varchar(255) NOT NULL DEFAULT '',
  `provider` varchar(128) NOT NULL DEFAULT '',
  `agent` varchar(255) NOT NULL DEFAULT '',
  `extra` text,
  `date` int(12) NOT NULL DEFAULT '0',
  `action` enum('banned','blocked','monitored','polled') NOT NULL DEFAULT 'monitored',
  PRIMARY KEY (`lid`),
  KEY `uid` (`uid`),
  KEY `ip` (`ip4`,`ip6`(16),`proxy-ip4`,`proxy-ip6`(16)),
  KEY `provider` (`provider`(15)),
  KEY `date` (`date`),
  KEY `action` (`action`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `xortify_servers` (
  `sid` mediumint(32) unsigned NOT NULL AUTO_INCREMENT,
  `server` varchar(255) NOT NULL DEFAULT '',
  `replace` varchar(255) NOT NULL DEFAULT '',
  `search` varchar(64) NOT NULL DEFAULT '',
  `online` tinyint(1) DEFAULT '0',
  `polled` int(12) NOT NULL DEFAULT '0',
  `user` varchar(64) NOT NULL DEFAULT '',
  `pass` varchar(32) NOT NULL DEFAULT '',
  PRIMARY KEY (`sid`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `xortify_emails` (
  `eid` mediumint(32) unsigned NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL DEFAULT '',
  `uid` int(13) NOT NULL DEFAULT '0',
  `count` int(26) NOT NULL DEFAULT '1',
  `encounter` int(13) NOT NULL DEFAULT '0',
  PRIMARY KEY (`eid`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;

CREATE TABLE `xortify_emails_links` (
  `elid` mediumint(64) unsigned NOT NULL AUTO_INCREMENT,
  `eid` mediumint(32) unsigned NOT NULL DEFAULT '0',
  `uid` int(13) NOT NULL DEFAULT '0',
  `ip` varchar(128) NOT NULL DEFAULT '127.0.0.1',
PRIMARY KEY (`elid`)
) ENGINE=INNODB DEFAULT CHARSET=utf8;