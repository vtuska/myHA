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
###

use strict;
use warnings;

use DBI;
use Term::ANSIColor qw(:constants);
use POSIX ':signal_h';
use Getopt::Std;
use node;

$|=1;

my (@pnodes, @anodes, $pnode, $anode, $pdict, $adict);
my ($outlines, $errlines, $rc);

sub usage {
        print "Usage: $0 -c config.pl [-s no_ssh|-m no_mysql] [-a active_node -p passive_node] [-f] [-h]\n";
        print "\t-c: Configuration file.\n";
        print "\t-s: No ssh check on the passive node.\n";
        print "\t-m: No mysql check on the passive node.\n";
        print "\t-a: Active node.\n";
        print "\t-p: Passive node.\n";
        print "\t-f: Force/Fix.\n";
        print "\t-x: Flip-Flop.\n";
        print "\t-h: Show help.\n";

	exit(0);
}

my %options;
getopts("c:a:p:smfxh",\%options);

usage() if $options{h} || !%options ;

my $cfg;
if ($options{c}) {
	require $options{c};
	$cfg = get_config();
}

if (scalar keys %{$cfg->{'nodes'}} != 2) {
	node::error(undef,"Node number != 2 in config hash!"); 
}

if ($options{a}) {
	my $key = $options{a};
	$anode = node->new($cfg->{'nodes'}, $key);
}

my $checkpflag = $node::_CHECK_BITMASK;

if ($options{m}) {
	$checkpflag = $checkpflag & ($node::_CHECK_BITMASK & ~$node::_CHECK_MYSQL); 
}
if ($options{s}) {
	$checkpflag = $checkpflag & ($node::_CHECK_BITMASK & ~$node::_CHECK_SH);
}

if ($options{p}) {
	my $key = $options{p};
	$pnode = node->new($cfg->{'nodes'}, $key, $checkpflag);
} else {
	foreach my $key (sort keys %{$cfg->{'nodes'}}) {
		if (defined($anode) && !(defined($pnode))) {
			if  ($key ne $anode->{'dict'}->{'node'}) {
				$pnode = node->new($cfg->{'nodes'}, $key, $checkpflag);
				last;
			}
		} else {
			my $tmpnewnode = node->new($cfg->{'nodes'}, $key);
			if ($tmpnewnode->{'dict'}->{'db'}->{'type'} eq 'ACTIVE') {
				$anode = $tmpnewnode;
			} else {
				$pnode = $tmpnewnode;
			}
		}
	}
}

if ($options{p} && $options{a} && ($options{a} eq $options{p})) {
	node::error(undef,"Active node can't be passive node at the same time!");
}

if (!($options{a}) && $options{x}) {
	my $tmpnode = $anode;
	$anode = $pnode;
	$pnode = $tmpnode;
}

if (!($anode) || !($pnode)) {
	node::error(undef,"I can't figure out ACTIVE/PASSIVE nodes automagically! Please be more specific and help a bit with proper configuration parameters!");
}

if($anode->{'dict'}->{'db'}->{'type'} eq 'ACTIVE') {
	if ($checkpflag & $node::_CHECK_MYSQL) {
		if ($pnode->{'dict'}->{'db'}->{'type'} eq 'ACTIVE') {
			node::error(undef,"Both node is ACTIVE!");
		}
	}

	if ($checkpflag & $node::_CHECK_SH) {
		if ($pnode->nat_unset($cfg->{'service'}->{'virts'},$options{f}) | $pnode->vip_unset($cfg->{'service'}->{'virts'},$options{f})) {
			$pnode->dolog("Do you want to continue [y/n]?",1);
			my $question = (<STDIN>);
			if ($question ne "y\n") {
				exit(-1);
			}
		}
	}

	$anode->vip_set($cfg->{'service'}->{'virts'},$options{f});
	$anode->nat_set($cfg->{'service'}->{'virts'},$options{f});

	foreach my $key (sort keys %{$cfg->{'service'}->{'virts'}}) {
		my $tmpnodes = {};
		$tmpnodes->{$key}->{'db'} = {%{$anode->{'dict'}->{'db'}}};
		$tmpnodes->{$key}->{'db'}->{'hostname'} = $key;
		$tmpnodes->{$key}->{'db'}->{'port'} = $cfg->{'service'}->{'virts'}->{$key}->{'port'};

		my $checkflag = $node::_CHECK_BITMASK & ~$node::_CHECK_SH & ~$node::_CHECK_FATAL;
		my $tmpnode = node->new($tmpnodes, $key, $checkflag);

		if (defined($tmpnode->{'dict'}->{'db'}->{'dbh'})) {
			$tmpnode->db_info();
			if ($anode->{'dict'}->{'db'}->{'server_id'} ne $tmpnode->{'dict'}->{'db'}->{'server_id'}) {
				$tmpnode->error("Something is wrong! Different server_ids!");
			} else {
				$tmpnode->dolog('VIP Connection OK: '.$tmpnode->{'dict'}->{'db'}->{'hostname'}.':'.$tmpnode->{'dict'}->{'db'}->{'port'}, 1);
			}
		} else {
			$tmpnode->warning("Can't connect to VIP: ".$tmpnode->{'dict'}->{'db'}->{'hostname'}.':'.$tmpnode->{'dict'}->{'db'}->{'port'});
			$tmpnode->warning("Do you want to continue [y/n]?");
			my $question = (<STDIN>);
			if ($question ne "y\n") {
				exit(-1);
			}
		}
	}
} else {
	if ($checkpflag & $node::_CHECK_MYSQL) {
		if ( $pnode->db_set_read_lock($options{f}) |
			$pnode->db_set_passive($options{f}) |
			$anode->db_set_read_lock($options{f}) ) {
				$pnode->warning("Do you want to continue [y/n]?");
				my $question = (<STDIN>);
				if ($question ne "y\n") {
					exit(-1);
				}
		}

		$pnode->db_get_replication_info();
		$anode->db_get_replication_info();
		if ($anode->db_check_replication_sync($pnode,$cfg->{'service'}->{'lagretry'},$cfg->{'service'}->{'lagsleep'},$options{f}) != 0) {
			$pnode->warning("Do you want to continue [y/n]?");
			my $question = (<STDIN>);
			if ($question ne "y\n") {
				exit(-1);
			}
		}
	}
	
	if ($checkpflag & $node::_CHECK_SH) {
		$pnode->vip_unset($cfg->{'service'}->{'virts'},$options{f});
		$pnode->nat_unset($cfg->{'service'}->{'virts'},$options{f});
	}
	
	$anode->vip_set($cfg->{'service'}->{'virts'},$options{f});
	$anode->nat_set($cfg->{'service'}->{'virts'},$options{f});
	$anode->db_set_active($options{f});

	if ($checkpflag & $node::_CHECK_MYSQL) {
		$pnode->dolog("Kill mysql connections? [if yes then type YES<Enter>]", 1);
		my $question = <STDIN>;
		if ($question eq "YES\n") {
			$pnode->db_kill();
		}
	}
}

node::purge();

exit(0);
