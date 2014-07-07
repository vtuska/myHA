#!/usr/bin/perl -w

###
#
# This file is part of myHA. Developed by: vtuska
# Tested and used on: RHEL5
#
# myHA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# myHA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with myHA.  If not, see <http://www.gnu.org/licenses/>.
#
###

###
# Description:
# 
# This script can change the active master in a master-slave, master(active)-master(passive) MySQL environment.
# 
# It does the following before and during the failover/failback:
# 
#    checking replication status on the slave
#    flushing tables with read lock on the master and slave before failover/failback
#    activating read_only status on the master and slave
#    removing virtual ip address from the master
#    adding virtual ip address to the slave
#    sending gratuitous ARP packets from the slave
#    pinging virtual ip address from the master
#    creating port redirection on the slave if it's needed
#    setting read/write status on the slave
#    killing inactive connections on the master
#
# Estimated failover-failback time is 10-20 seconds.
# 
# The recommended type of the MySQL HA configuration: master(active)-master(passive)
# 
# Usage:
# 
# Preparation:
# 
# ssh -A [ master/slave ]
# 
# sudo -s -E
# 
# cd myHA
# 
# vi config.pl
# 
# Dry run:
# 
# ./myHA.pl config.pl
# 
# Live run:
# 
# ./myHA.pl config.pl --yes-I-know-what-I-am-doing
###

use strict;
use warnings;

#check db state before any activity (too many running sql queries...?)

use DBI;
use Term::ANSIColor qw(:constants);
use POSIX ':signal_h';
use node;

$|=1;

if ($#ARGV < 0) {
	node::dolog("Usage: ./myHA.pl [config file] [--yes-I-know-what-I-am-doing]", 1);
	exit(0);
}

require $ARGV[0];
my $cfg = get_config();

my ($pnode, $anode, $pdict, $adict);
my ($outlines, $errlines, $rc);

my $i = 0;
foreach my $node (@{$cfg->{'nodes'}}) {
	my $dbnode = node->new($node, $i);
	node::dolog('General Information (node'.$i.')', 1);
	$dbnode->db_info;

	my $dict;
	node::dolog('Checking slave status (node'.$i.')...', 1);
	$dict = $dbnode->db_get_dict('SHOW SLAVE STATUS');

	$dbnode->db_check_dict($dict->[0],'Slave_IO_Running', 'Yes');
	$dbnode->db_check_dict($dict->[0],'Slave_SQL_Running', 'Yes');
	$dbnode->db_check_dict($dict->[0],'Relay_Master_Log_File', $dict->[0]->{'Master_Log_File'});
	$dbnode->db_check_dict($dict->[0],'Exec_Master_Log_Pos', $dict->[0]->{'Read_Master_Log_Pos'});

	$dict = $dbnode->db_get_dict('select @@global.read_only');
	node::dolog('@@global.read_only: ');
	node::dolog('Checking read_only status (node'.$i.')...', 1);
	if ($dict->[0]->{'@@global.read_only'} == 1) {
		node::dolog('This is a PASSIVE member!', 1);
		$pnode=$dbnode;
	} else {
		node::dolog('This is an ACTIVE member!', 1);
		$anode=$dbnode;
	}
	node::dolog("($dict->[0]->{'@@global.read_only'})");
	
	$i += 1;
}

if ($i>2) { node:error("Too many nodes in the configuration hash! (Only 2 allowed)"); }
if (!defined($anode)) { node::error("Missing active node!"); }
if (!defined($pnode)) { node::error("Missing passive node!"); }

###
if (($#ARGV > 0) && ($ARGV[1] eq "--yes-I-know-what-I-am-doing" )) {
	node::dolog("Fasten your seatbelts!", 1);
} else {
	node::dolog("Phew, It was a dry run!", 1);
	exit(0);
}
###

node::dolog("Current threadid(active): ".$anode->db_get_threadid());
node::dolog('Trying to get read lock on the active node...', 1);
$anode->db_read_lock(0,1);
$anode->db_read_lock(1,0);
node::dolog('Read lock acquired!', 1);

node::dolog('Setting read only mode on the active node...', 1);
node::dolog('set @@global.read_only=1', 1);
$anode->db_execute('set @@global.read_only=1', 1);
if ($anode->db_get_dict('select @@global.read_only')->[0]->{'@@global.read_only'}) {
	node::dolog('Read only mode has been set on the active node!', 1);
} else {
	node::error('Can not set @@global.read_only to 1!');
}

node::dolog("Current threadid(passive): ".$pnode->db_get_threadid());
node::dolog('Trying to get read lock on the passive node...', 1);
$pnode->db_read_lock(0,1);
$pnode->db_read_lock(1,0);
node::dolog('Read lock acquired!', 1);

$adict = $anode->db_get_dict('SHOW MASTER STATUS');
$pdict = $pnode->db_get_dict('SHOW SLAVE STATUS');

node::dolog('Checking replication threads on the passive node', 1);
$pnode->db_check_dict($pdict->[0],'Slave_IO_Running', 'Yes', 1);
$pnode->db_check_dict($pdict->[0],'Slave_SQL_Running', 'Yes', 1);

my $lagretry = $cfg->{'service'}->{'lagretry'};

node::dolog('Checking replication state on the passive node...', 1);
do {
	sleep($cfg->{'service'}->{'lagsleep'});
	$rc = 0;
	$rc += $pnode->db_check_dict($pdict->[0],'Relay_Master_Log_File', $pdict->[0]->{'Master_Log_File'});
	$rc += $pnode->db_check_dict($pdict->[0],'Exec_Master_Log_Pos', $pdict->[0]->{'Read_Master_Log_Pos'});
	$rc += $pnode->db_check_dict($pdict->[0],'Master_Log_File', $adict->[0]->{'File'});
	$rc += $pnode->db_check_dict($pdict->[0],'Read_Master_Log_Pos', $adict->[0]->{'Position'});
	node::dolog("Rc: ".$rc." Retry: ".$lagretry);
	$lagretry -= 1;
} while(($rc != 0) && ($lagretry != 0));

if ($rc) {
	$pnode->db_check_dict($pdict->[0],'Relay_Master_Log_File', $pdict->[0]->{'Master_Log_File'}, 1);
	$pnode->db_check_dict($pdict->[0],'Exec_Master_Log_Pos', $pdict->[0]->{'Read_Master_Log_Pos'}, 1);
	$pnode->db_check_dict($pdict->[0],'Master_Log_File', $adict->[0]->{'File'}, 1);
	$pnode->db_check_dict($pdict->[0],'Read_Master_Log_Pos', $adict->[0]->{'Position'}, 1);
}
node::dolog('Replication state: Synched!', 1);

$anode->db_get_dict('SHOW BINARY LOGS');
$anode->db_get_dict('SHOW MASTER STATUS');
$anode->db_get_dict('SHOW SLAVE STATUS');
$pnode->db_get_dict('SHOW BINARY LOGS');
$pnode->db_get_dict('SHOW MASTER STATUS');
$pnode->db_get_dict('SHOW SLAVE STATUS');

node::dolog('Passive node ip list:');
($outlines, $errlines, $rc) = $pnode->cmd_execute("/sbin/ip add list");
if ($rc != 0) {
	node::error("Can't get ip addr list!");
}

node::dolog("Release virtual ip address on the active node...", 1);
($outlines, $errlines, $rc) = $anode->cmd_execute('/sbin/ip addr list');
($outlines, $errlines, $rc) = $anode->cmd_execute('/sbin/ip addr del '."$cfg->{'service'}->{'virtip'}".'/'."$cfg->{'service'}->{'virtnet'}".' dev '.$anode->get_virtif());

node::dolog('Setting read/write mode on the (ex)passive node...', 1);
node::dolog('set @@global.read_only=0', 1);
$pnode->db_execute('set @@global.read_only=0');
if ($pnode->db_get_dict('select @@global.read_only')->[0]->{'@@global.read_only'} == 0) {
	node::dolog("Read/write mode has been set on the (ex)passive node!", 1);
} else {
	node::error('Can not set @@global.read_only to 0!');
}

node::dolog("Setting virtual ip address on the (ex)passive node...", 1);
($outlines, $errlines, $rc) = $pnode->cmd_execute('/sbin/ip addr list');
($outlines, $errlines, $rc) = $pnode->cmd_execute('/sbin/ip addr add '."$cfg->{'service'}->{'virtip'}".'/'."$cfg->{'service'}->{'virtnet'}".' dev '.$pnode->get_virtif().' label '.$pnode->get_virtlabel());
($outlines, $errlines, $rc) = $pnode->cmd_execute('/sbin/arping -A -c 4 -I '.$pnode->get_virtif().' '."$cfg->{'service'}->{'virtip'}");

node::dolog('Checking virtual ip address accessibility from the (ex)active node...', 1);
($outlines, $errlines, $rc) = $anode->cmd_execute('/bin/ping -c 3 '.$cfg->{'service'}->{'virtip'});
if ($rc != 0) {
	node::error("Check the virtip accessibility ASAP!");
}

($outlines, $errlines, $rc) = $anode->cmd_execute('/sbin/arp -an|grep '.$cfg->{'service'}->{'virtip'});

if (defined($pnode->get_virtport())) {
	node::dolog('Setting port redirection for non standard port on the (ex)passive node...', 1);
	($outlines, $errlines, $rc) = $pnode->cmd_execute('/sbin/iptables -A PREROUTING -t nat -i '.$pnode->get_virtif().' -p tcp --dst '.$cfg->{'service'}->{'virtip'}.' --dport '.$pnode->get_virtport().' -j REDIRECT --to-port '.$pnode->get_port());
}
if (defined($anode->get_virtport())) {
	node::dolog('Removing port redirection for non standard port on the (ex)active node...', 1);
	($outlines, $errlines, $rc) = $anode->cmd_execute('/sbin/iptables -D PREROUTING -t nat -i '.$anode->get_virtif().' -p tcp --dst '.$cfg->{'service'}->{'virtip'}.' --dport '.$anode->get_virtport().' -j REDIRECT --to-port '.$anode->get_port());
}

print '', RESET;
#node::dolog("Sleeping...", 1);
#sleep(1);
node::dolog("Kill mysql connections on the (ex)active node? [if yes then type YES<Enter>]", 1);
my $cont = <STDIN>;
chomp($cont);

if ($cont eq "YES") {
	$anode->db_kill();
}

node::purge();

exit(0);
