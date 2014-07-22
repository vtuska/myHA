package node;

###
#
# This file is part of myHA. Developed by: vtuska
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


use strict;
use warnings;

use DBI;
use Term::ANSIColor qw(:constants);
use POSIX qw(:signal_h :errno_h :sys_wait_h);
use IPC::Open3;
use IO::Select;

sub _autoflush {
   my $h = select($_[0]); $|=$_[1]; select($h);
}

my $_localhostname = `hostname`;
my $_timeout = 3;

my @register;

my ($sec,$min,$hour,$day,$mon,$year_1900,$wday,$yday,$isdst)=localtime;
my $ts =  sprintf("%04d%02d%02d%02d%02d%02d", ($year_1900+1900),($mon+1),$day,$hour,$min,$sec);

open(*LOG, ">./mysql.$ts.log");
_autoflush(\*LOG,1);
_autoflush(\*STDOUT,1);

sub new {
	my $class = shift;
	my $config = shift;
	my $node = shift;
	
	my $self = { };

	dolog("node new() start");

	$self->{'dict'}->{'node'} = $node;
	$self->{'dict'}->{'db'}->{'hostname'} = $config->{'db'}->{'hostname'};
	$self->{'dict'}->{'db'}->{'dsn'} = "DBI:mysql:database=$config->{'db'}->{'database'};host=$config->{'db'}->{'hostname'};port=$config->{'db'}->{'port'}";
	$self->{'dict'}->{'db'}->{'user'} = $config->{'db'}->{'user'};
	$self->{'dict'}->{'db'}->{'port'} = $config->{'db'}->{'port'};

	if (!defined($config->{'db'}->{'password'})) {
		print "DB password (".$self->{'dict'}->{'node'}." ".$self->{'dict'}->{'db'}->{'hostname'}."): ";
		system('/bin/stty', '-echo');
		$self->{'dict'}->{'db'}->{'password'} = <STDIN>;
		chomp($self->{'dict'}->{'db'}->{'password'});
		system('/bin/stty', 'echo');
	} else {
		$self->{'dict'}->{'db'}->{'password'} = $config->{'db'}->{'password'};
	}

	$self->{'dict'}->{'db'}->{'timeout'} = $config->{'db'}->{'timeout'};
	$self->{'dict'}->{'db'}->{'maxretry'} = $config->{'db'}->{'maxretry'};
	$self->{'dict'}->{'db'}->{'virtif'} = $config->{'db'}->{'virtif'};
	if (!defined($config->{'db'}->{'virtlabel'})) {
		$self->{'dict'}->{'db'}->{'virtlabel'} = $config->{'db'}->{'virtif'}.':'.$config->{'db'}->{'port'};
	} else {
		$self->{'dict'}->{'db'}->{'virtlabel'} = $config->{'db'}->{'virtlabel'};
	}
	$self->{'dict'}->{'db'}->{'virtport'} = $config->{'db'}->{'virtport'};
	$self->{'dict'}->{'db'}->{'dbh'} = DBI->connect($self->{'dict'}->{'db'}->{'dsn'}, $self->{'dict'}->{'db'}->{'user'}, $self->{'dict'}->{'db'}->{'password'}, {'RaiseError' => 1, 'mysql_auto_reconnect' => 0});

	$self->{'dict'}->{'ssh'}->{'user'} = $config->{'ssh'}->{'user'};
	$self->{'dict'}->{'ssh'}->{'hostname'} = $config->{'ssh'}->{'hostname'};
	$self->{'dict'}->{'ssh'}->{'port'} = $config->{'ssh'}->{'port'};
	$self->{'dict'}->{'ssh'}->{'timeout'} = $config->{'ssh'}->{'timeout'};
	$self->{'dict'}->{'ssh'}->{'socket'} = $config->{'ssh'}->{'socket'};

	ssh_open_master($self);

	if (!defined($config->{'sudo'}->{'password'})) {
		print "Sudo password (".$self->{'dict'}->{'node'}." ".$self->{'dict'}->{'ssh'}->{'hostname'}."): ";
		system('/bin/stty', '-echo');
		$self->{'dict'}->{'sudo'}->{'password'} = <STDIN>;
		system('/bin/stty', 'echo');
	} else {
		$self->{'dict'}->{'sudo'}->{'password'} = $config->{'sudo'}->{'password'}."\n";
	}

	my ($outlines, $errlines, $rc) = remote_execute($self, "hostname");

	$self->{'dict'}->{'ssh'}->{'real_hostname'} = @{$outlines}[1];
	if ($self->{'dict'}->{'ssh'}->{'real_hostname'} eq $_localhostname) {
		dolog("LOCAL");
		$self->{'dict'}->{'ssh'}->{'location'} = "LOCAL";
	} else {
		$self->{'dict'}->{'ssh'}->{'location'} = "REMOTE";
		dolog("REMOTE");
	}

	bless $self, $class;

	push @register, $self;

	dolog("node new() end");
	return $self;
}

sub get_dict {
	my $self = shift;
	my $key = shift;
	my $dict = shift || 'dict';

	return $self->{$dict}->{$key};
}

sub set_dict {
	my $self = shift;
	my $key = shift;
	my $value = shift;
	my $dict = shift || 'dict';

	$self->{$dict}->{$key} = $value;
}

sub db_info {
	my $self = shift;
	dolog("db_info() start");

no warnings;
	dolog("Node: ".$self->{'dict'}->{'node'}."
	Host: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_hostinfo'}."
	ServerInfo: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_serverinfo'}."
	Stat: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_stat'}."
	ProtoInfo: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_protoinfo'}."
	ThreadId: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_thread_id'}."
	Info: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_info'}."
	InsertId: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_insertid'}."
	Errno: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_errno'}."
	Error: ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_error'}, 1);
use warnings;

	dolog("db_info() end");
}

sub dolog {
	my $message = shift;
	my $debug = shift;

	my ($sec,$min,$hour,$day,$mon,$year_1900,$wday,$yday,$isdst)=localtime;
	$ts =  sprintf("%04d-%02d-%02d %02d:%02d:%02d", ($year_1900+1900),($mon+1),$day,$hour,$min,$sec);
	$message = $ts." - ".$message."\n";
	if (defined($debug)) { print WHITE $message; }
	print LOG $message;
	return $message;
}

sub error {
	my $message = shift;

	print RED dolog("Fatal error: ".$message, 1)."\n";
	print "", RESET;

	purge();

	exit(-1);
}

sub warning {
	my $message = shift;

	print YELLOW dolog("Warning: ".$message, 1)."\n";
}

sub db_get_dict {
	my $self = shift;
	my $query = shift;
	my $timeout = shift;
	my $sth;
	my $dict = [];

	dolog("db_get_dict() start");
	if ($sth = _db_execute($self, $query)) {

		my $names = $sth->{'NAME'};
		my $numFields = $sth->{'NUM_OF_FIELDS'};
		my $row = 0;
		while (my $value = $sth->fetchrow_arrayref) {
			for (my $i = 0;  $i < $numFields;  $i++) {
				$dict->[$row]->{$$names[$i]} = $$value[$i];
				my $log = "row: ".$row.", column: ".$$names[$i].", value: ".(defined($$value[$i]) ? $$value[$i] : 'NULL');
				dolog($log);
			}
			$row += 1;
		}
		$sth->finish;
	}

	dolog("db_get_dict() end");
	return $dict;
}

sub db_check_dict {
	my $self = shift;
	my $dict = shift;
	my $key = shift;
	my $value = shift || 'undef';
	my $fatal = shift;

	dolog("db_check_dict() start");
	dolog("(".$key."/".$value.")", 1);

	if (!defined($dict->{$key})) {
		$dict->{$key} = 'NULL';
	}

	if ($dict->{$key} eq $value) {
		print GREEN "OK ($value)\n";
	} else {
		if ($fatal) {
			error("$key: $dict->{$key} (expected: $value)!\n");
		} else {
			warning("$key: $dict->{$key} (expected: $value)!\n");
			return 1;
		}
	}
	dolog("db_check_dict() end");
	return 0;
}

sub db_execute {
	my $self = shift;
	my $query = shift;
	my $timeout = shift;
	my $sth;

	dolog("db_execute(".$query.") start");
	if ($sth = _db_execute($self, $query, $timeout)) {
		$sth->finish;
	}

	dolog("db_execute() end");
	return 0;
}

sub _db_execute {
	my $self = shift;
	my $query = shift;
	my $timeout = shift || $self->{'dict'}->{'db'}->{'timeout'};
	my $sth = $self->{'dict'}->{'db'}->{'dbh'}->prepare($query);
 
	dolog("_db_execute(".$query.",".$timeout.") start");

	my $mask = POSIX::SigSet->new( SIGALRM );
	my $action = POSIX::SigAction->new(
		sub { die("SIGALRM: timeout") },
		$mask,
	);

	my $oldaction = POSIX::SigAction->new();
	sigaction( SIGALRM, $action, $oldaction );
	eval {
		alarm($timeout);

		if (!$sth || !$sth->execute) {
			error("err: ".$self->{'dict'}->{'db'}->{'dbh'}->err."\nerrstr: ".$self->{'dict'}->{'db'}->{'dbh'}->errstr."\nstate: ".$self->{'dict'}->{'db'}->{'dbh'}->state);
		}
		alarm(0);
	};
	alarm(0);
	sigaction( SIGALRM, $oldaction );

	dolog("_db_execute() end");

	if ( $@ =~ /timeout/) { 
		error("Timeout err: ".$query." ".$@);
	} else {
		return $sth;
	}
}

sub db_kill {
	my $self = shift;

	db_close($self);
	$self->{'dict'}->{'db'}->{'dbh'} = DBI->connect($self->{'dict'}->{'db'}->{'dsn'}, $self->{'dict'}->{'db'}->{'user'}, $self->{'dict'}->{'db'}->{'password'}, {'RaiseError' => 1, 'mysql_auto_reconnect' => 0});
	foreach my $tmp (@{db_get_dict($self,'SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST')}) {
		if (($tmp->{'ID'} != $self->{'dict'}->{'db'}->{'dbh'}->{'mysql_thread_id'}) && ($tmp->{'USER'} ne 'repl') && ($tmp->{'USER'} ne 'system user')) {
			dolog('Murder '.$tmp->{'USER'}.'('.$tmp->{'ID'}.')', 1);
			my $sth = $self->{'dict'}->{'db'}->{'dbh'}->prepare("KILL $tmp->{'ID'}");
			$sth->execute;
		}
	}
}

sub db_read_lock {
	my $self = shift;
	my $fatal = shift;
	my $kill = shift;
	my $count = 0;
my $sth;

	dolog("db_read_lock() start");

	while (db_execute($self, 'FLUSH TABLES WITH READ LOCK', $self->{'dict'}->{'db'}->{'timeout'})) {
		dolog("Trying to acquire read_lock...".$count);
		$count += 1;
		if ($count == $self->{'dict'}->{'db'}->{'maxretry'}) {
			if ($kill) {
				db_kill($self);
			}
			if ($fatal) {
				error("Can't acquire the GLOBAL READ LOCK in time (timeout: $self->{'dict'}->{'db'}->{'timeout'}, maxretry: $self->{'dict'}->{'db'}->{'maxretry'})!");
			} else {
				last;
			}
		}
	} 
	dolog("db_read_lock() end");
}

sub db_close {
	my $self = shift;

	dolog("db_close() start");
	$self->{'dict'}->{'db'}->{'dbh'}->disconnect;
	dolog("db_close() end");
}

sub REAPER {
	my $pid;

	$pid = waitpid(-1, &WNOHANG);

	if ($pid == -1) {
		# no child waiting. Ignore it.
	} elsif (WIFEXITED($?)) {
		dolog("Process $pid exited.");
	} else {
		dolog("False alarm on $pid.\n");
	}

	$SIG{CHLD} = \&REAPER; 
}

sub ssh_open_master {
	my $self = shift;

	dolog("ssh_open_master() start");

	$SIG{CHLD} = \&REAPER;

	my $pid;
	unless ($pid = fork()) {
		open(STDOUT, '>', '/dev/null');
		open(STDERR, '>', '/dev/null');

		my $ssh_cmd = 'ssh -N -M -S '.$self->{'dict'}->{'ssh'}->{'socket'}.' -l '.$self->{'dict'}->{'ssh'}->{'user'}.' '.$self->{'dict'}->{'ssh'}->{'hostname'};
		dolog("ssh_cmd: ".$ssh_cmd);
		exec($ssh_cmd);
		exit();
	}

	dolog("ssh_open_master() end");
}

sub ssh_close_master {
	my $self = shift;

	open(STDOUT, '>', '/dev/null');
	open(STDERR, '>', '/dev/null');
	my $ssh_cmd = 'ssh -S '.$self->{'dict'}->{'ssh'}->{'socket'}.' -l '.$self->{'dict'}->{'ssh'}->{'user'}.' -O exit '.$self->{'dict'}->{'ssh'}->{'hostname'};
	dolog("ssh_cmd: ".$ssh_cmd);
	system($ssh_cmd);
}

sub remote_execute {
	my $self = shift;
	my $cmd = shift;
	my @outlines;
	my @errlines;

	dolog("remote_execute(".$cmd.") start");

	my $mask = POSIX::SigSet->new( SIGALRM );
	my $pid;
	my $action = POSIX::SigAction->new(
		sub { kill(9, ${\$pid}); die("SIGALRM: timeout"); },
		$mask,
	);

	my $oldaction = POSIX::SigAction->new();
	sigaction( SIGALRM, $action, $oldaction );

	my $rc = 0;
	eval {
		alarm($self->{'dict'}->{'ssh'}->{'timeout'});

		my $ssh_cmd = 'ssh -tt -S '.$self->{'dict'}->{'ssh'}->{'socket'}.' -l '.$self->{'dict'}->{'ssh'}->{'user'}.' -p '.$self->{'dict'}->{'ssh'}->{'port'}.' '.$self->{'dict'}->{'ssh'}->{'hostname'}.' "(sudo -k -S -p sudo_password: -- '.$cmd.')"';
		dolog("ssh_cmd: ".$ssh_cmd);

		$pid = open3(*IN, *OUT, *ERR, $ssh_cmd);

		my $sel = new IO::Select();

		$sel->add(\*OUT);
		$sel->add(\*ERR);

		my($err,$out)=('','');

		while(1){
			foreach my $h ($sel->can_read) {
				my $buf = '';

				if ($h eq \*ERR) {
					sysread(\*ERR,$buf,4096);
					if ($buf) {
						$err .= $buf;
					}
				} else {
					sysread(\*OUT,$buf,4096);
					if ($buf) {
						$out .= $buf;
					}
				}
			}
			if ($out =~ /sudo_password:/) {
				last;
			}
		}

		_autoflush(\*IN, 1);
		_autoflush(\*OUT, 1);
		_autoflush(\*ERR, 1);

		$SIG{CHLD} = \&REAPER;

		print IN $self->{'dict'}->{'sudo'}->{'password'};
		@outlines = <OUT>;
		@errlines = <ERR>;
		dolog("STDOUT:\n".join(" ",@outlines));
		dolog("STDERR:\n".join(" ",@errlines));

		alarm(0);
	};

	alarm(0);
	sigaction( SIGALRM, $oldaction );

	close(\*IN);
	close(\*OUT);
	close(\*ERR);

	if ( $@ =~ /timeout/) { 
		error("Something is wrong. SSH execution timeout!");
	}

	if ( $rc != 0 ) { 
		warning("Something is wrong. SSH execution return code is not 0! ($cmd)");
	}

	dolog("remote_execute() end");
	return (\@outlines, \@errlines, $rc);
}

sub local_execute {
	my $self = shift;
	my $cmd = shift;

	my (@outlines, @errlines);

	dolog("local_execute(".$cmd.") start");

	my $mask = POSIX::SigSet->new( SIGALRM );
	my $pid;
	my $action = POSIX::SigAction->new(
		sub { kill(9, ${\$pid}); die("SIGALRM: timeout"); },
		$mask,
	);

	my $oldaction = POSIX::SigAction->new();
	sigaction( SIGALRM, $action, $oldaction );

	my $rc = 0;
	eval {
		alarm($self->{'dict'}->{'ssh'}->{'timeout'});

		my $local_cmd = 'sudo -k -S -p sudo_password: -- '.$cmd;
		dolog("local_cmd: ".$local_cmd);

		$pid = open3(*IN, *OUT, *ERR, $local_cmd);
		_autoflush(\*IN, 1);
		_autoflush(\*OUT, 1);
		_autoflush(\*ERR, 1);

		$SIG{CHLD} = \&REAPER;

		print IN $self->{'dict'}->{'sudo'}->{'password'}; 
		@outlines = <OUT>;
		@errlines = <ERR>;
		dolog("STDOUT:\n".join(" ",@outlines));
		dolog("STDERR:\n".join(" ",@errlines));

		alarm(0);
	};
	
	alarm(0);
	sigaction( SIGALRM, $oldaction );

	close(\*IN);
	close(\*OUT);
	close(\*ERR);

	if ( $@ =~ /timeout/) { 
		error("Something is wrong. Local execution timeout!");
	}

	if ( $rc != 0 ) { 
		warning("Something is wrong. Local execution return code is not 0($rc)! ($cmd)");
	}

	dolog("local_execute() end");

	return (\@outlines, \@errlines, $rc);
}

sub cmd_execute {
	my $self = shift;
	my $cmd = shift;

	dolog("cmd_execute(".$cmd.") start");

	my ($outlines, $errlines, $rc);

	if ($self->{'dict'}->{'ssh'}->{'location'} eq "LOCAL") {
		($outlines, $errlines, $rc) = local_execute($self, $cmd);
	} else {
		($outlines, $errlines, $rc) = remote_execute($self, $cmd);
	}

	dolog("cmd_execute() end");
	return ($outlines, $errlines, $rc);
}

sub purge {
	my $self = shift;
	dolog("purge() start");

	foreach my $tmp (@register) {
		ssh_close_master($tmp);
		db_close($tmp);
	}

	dolog("purge() end");
}

1;
