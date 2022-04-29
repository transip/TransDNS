CREATE TABLE `Domains` (
  `domain` varchar(256) default NULL,
  `serial` varchar(10) default NULL,
  `id` int(10) unsigned NOT NULL auto_increment,
  PRIMARY KEY  (`id`),
  KEY `domain` (`domain`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;

CREATE TABLE `AXFR_ACL` (
  `ip` varchar(80) default NULL,
  `id` int(10) unsigned NOT NULL auto_increment,
  PRIMARY KEY  (`id`),
  INDEX `searchOnIp` (`ip`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;

CREATE TABLE `Notifies` (
  `domain` varchar(256) default NULL,
  `ts`     TIMESTAMP default NOW(),
  `source` varchar(256) default NULL,
  `id` int(10) unsigned NOT NULL auto_increment,
  PRIMARY KEY  (`id`),
  KEY `domain` (`domain`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;

CREATE TABLE `Records` (
  `name` varchar(256) default NULL,
  `qtype` int(6) default NULL,
  `ttl` int(10) unsigned default NULL,
  `rdata` varchar(1024) default NULL,
  `updated` tinyint(4) default NULL,
  `deleted` tinyint(4) default NULL,
  `id` int(10) unsigned NOT NULL auto_increment,
  `domain_id` int(10) unsigned default NULL,
  PRIMARY KEY  (`id`),
  KEY `name` (`name`),
  KEY `domain_id` (`domain_id`),
  KEY `updated` (`updated`),
  KEY `qtype` (`qtype`),
  KEY `transdnsupdate` (`deleted`,`updated`)
) ENGINE=InnoDB AUTO_INCREMENT=0 DEFAULT CHARSET=latin1;
