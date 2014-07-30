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

our $_CHECK_FATAL = 1;
our $_CHECK_SH = 2;
our $_CHECK_MYSQL = 4;
our $_CHECK_BITMASK = ($_CHECK_FATAL | $_CHECK_SH | $_CHECK_MYSQL );

sub new {
	my $class = shift;
	my $cfgnode = shift;
	my $key = shift;
	my $nodeconfig = $cfgnode->{$key};
	my $checkflag = shift;

	if (!defined($checkflag)) {
		$checkflag = $_CHECK_BITMASK;
	}
	
	my $self = { };
	bless $self, $class;
	push @register, $self;

	$self->{'dict'}->{'node'} = $key;
	$self->{'log'} = '('.$key.'): ';

	dolog($self,"node new() start");

	if (!defined($nodeconfig)) {
		error($self,"Missing node $key");
	}

	$self->{'dict'}->{'db'} = {%{$nodeconfig->{'db'}}};
	$self->{'dict'}->{'db'}->{'dsn'} = "DBI:mysql:database=".$nodeconfig->{'db'}->{'database'}.";host=".$nodeconfig->{'db'}->{'hostname'}.";port=".$nodeconfig->{'db'}->{'port'};
	if (!defined($nodeconfig->{'db'}->{'password'})) {
		print "DB password (".$self->{'dict'}->{'node'}." ".$self->{'dict'}->{'db'}->{'hostname'}."): ";
		system('/bin/stty', '-echo');
		$self->{'dict'}->{'db'}->{'password'} = <STDIN>;
		chomp($self->{'dict'}->{'db'}->{'password'});
		system('/bin/stty', 'echo');
	}

	if (!defined($nodeconfig->{'db'}->{'virtlabel'})) {
		$self->{'dict'}->{'db'}->{'virtlabel'} = $nodeconfig->{'db'}->{'virtif'}.':'.$nodeconfig->{'db'}->{'port'};
	}
	if ($checkflag & $_CHECK_MYSQL) {
		$self->{'dict'}->{'db'}->{'dbh'} = DBI->connect($self->{'dict'}->{'db'}->{'dsn'}, $self->{'dict'}->{'db'}->{'user'}, $self->{'dict'}->{'db'}->{'password'}, {'RaiseError' => $checkflag&$_CHECK_FATAL, 'mysql_auto_reconnect' => 0});

		if (defined($self->{'dict'}->{'db'}->{'dbh'})) {
			my $dict;
			$dict = db_get_dict($self, 'select @@global.read_only,@@global.server_id');
			$self->{'dict'}->{'db'}->{'server_id'} = $dict->[0]->{'@@global.server_id'};
			dolog($self,'Checking read_only status ...', 1);
			if ($dict->[0]->{'@@global.read_only'} == 1) {
				dolog($self,'This is a PASSIVE member!', 1);
				$self->{'dict'}->{'db'}->{'type'} = 'PASSIVE';
			} else {
				dolog($self,'This is an ACTIVE member!', 1);
				$self->{'dict'}->{'db'}->{'type'} = 'ACTIVE';
			}
			dolog($self,"($dict->[0]->{'@@global.read_only'},$dict->[0]->{'@@global.server_id'})");
		} else {
			warning($self,"Can't connect to DB server");
		}
	}

	if ($checkflag & $_CHECK_SH) {
		$self->{'dict'}->{'ssh'} = {%{$nodeconfig->{'ssh'}}};
		$self->{'dict'}->{'sudo'} = {%{$nodeconfig->{'sudo'}}};

		ssh_open_master($self);

		if (!defined($self->{'dict'}->{'sudo'}->{'password'})) {
			print "Sudo password (".$self->{'dict'}->{'node'}." ".$self->{'dict'}->{'ssh'}->{'hostname'}."): ";
			system('/bin/stty', '-echo');
			$self->{'dict'}->{'sudo'}->{'password'} = <STDIN>;
			system('/bin/stty', 'echo');
		} else {
			$self->{'dict'}->{'sudo'}->{'password'} .= "\n";
		}

		my ($outlines, $errlines, $rc) = remote_execute($self, "hostname");

		$self->{'dict'}->{'ssh'}->{'real_hostname'} = @{$outlines}[1];
		if ($self->{'dict'}->{'ssh'}->{'real_hostname'} eq $_localhostname) {
			dolog($self,"LOCAL");
			$self->{'dict'}->{'ssh'}->{'location'} = "LOCAL";
		} else {
			$self->{'dict'}->{'ssh'}->{'location'} = "REMOTE";
			dolog($self,"REMOTE");
		}
	}

	dolog($self,"node new() end");
	return $self;
}

sub db_info {
	my $self = shift;
	dolog($self,"db_info() start");

no warnings;
	dolog($self,"Node: ".$self->{'dict'}->{'node'}."
	Server_Id: ".$self->{'dict'}->{'db'}->{'server_id'}."
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

	dolog($self,"db_info() end");
}

sub dolog {
	my $self = shift;
	my $message = shift;
	my $debug = shift;

	my ($sec,$min,$hour,$day,$mon,$year_1900,$wday,$yday,$isdst)=localtime;
	$ts =  sprintf("%04d-%02d-%02d %02d:%02d:%02d", ($year_1900+1900),($mon+1),$day,$hour,$min,$sec);
	if ((ref($self) eq 'node') && $self->{'log'}) {
		$ts = $ts.' - '.$self->{'log'};
	}
	$message = $ts.' '.$message."\n";
	if (defined($debug)) { print WHITE $message; }
	print LOG $message;
	return $message;
}

sub error {
	my $self = shift;
	my $message = shift;

	print RED dolog($self,"Fatal error: ".$message);
	print "", RESET;

	purge();

	exit(-1);
}

sub warning {
	my $self = shift;
	my $message = shift;

	print YELLOW dolog($self,"Warning: ".$message);
	print "", RESET;
}

sub db_get_dict {
	my $self = shift;
	my $query = shift;
	my $timeout = shift;
	my $sth;
	my $dict = [];

	dolog($self,"db_get_dict() start");
	if ($sth = _db_execute($self, $query)) {

		my $names = $sth->{'NAME'};
		my $numFields = $sth->{'NUM_OF_FIELDS'};
		my $row = 0;
		while (my $value = $sth->fetchrow_arrayref) {
			for (my $i = 0;  $i < $numFields;  $i++) {
				$dict->[$row]->{$$names[$i]} = $$value[$i];
				my $log = "row: ".$row.", column: ".$$names[$i].", value: ".(defined($$value[$i]) ? $$value[$i] : 'NULL');
				dolog($self,$log);
			}
			$row += 1;
		}
		$sth->finish;
	}

	dolog($self,"db_get_dict() end");
	return $dict;
}

sub db_check_dict {
	my $self = shift;
	my $dict = shift;
	my $key = shift;
	my $value = shift || 'undef';
	my $fatal = shift;

	dolog($self,"db_check_dict() start");
	dolog($self,"(".$key."/".$value.")", 1);

	if (!defined($dict->{$key})) {
		$dict->{$key} = 'NULL';
	}

	if ($dict->{$key} eq $value) {
		print GREEN "OK ($value)\n";
		print "", RESET;
	} else {
		if ($fatal) {
			error($self,"$key: $dict->{$key} (expected: $value)!\n");
		} else {
			warning($self,"$key: $dict->{$key} (expected: $value)!\n");
			return 1;
		}
	}
	dolog($self,"db_check_dict() end");
	return 0;
}

sub db_execute {
	my $self = shift;
	my $query = shift;
	my $timeout = shift;
	my $sth;

	dolog($self,"db_execute(".$query.") start");
	if ($sth = _db_execute($self, $query, $timeout)) {
		$sth->finish;
	}

	dolog($self,"db_execute() end");
	return 0;
}

sub _db_execute {
	my $self = shift;
	my $query = shift;
	my $timeout = shift || $self->{'dict'}->{'db'}->{'timeout'};
	my $sth = $self->{'dict'}->{'db'}->{'dbh'}->prepare($query);
 
	dolog($self,"_db_execute(".$query.",".$timeout.") start");

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
			error($self,"err: ".$self->{'dict'}->{'db'}->{'dbh'}->err."\nerrstr: ".$self->{'dict'}->{'db'}->{'dbh'}->errstr."\nstate: ".$self->{'dict'}->{'db'}->{'dbh'}->state);
		}
		alarm(0);
	};
	alarm(0);
	sigaction( SIGALRM, $oldaction );

	dolog($self,"_db_execute() end");

	if ( $@ =~ /timeout/) { 
		error($self,"Timeout err: ".$query." ".$@);
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
			dolog($self,'Murder '.$tmp->{'USER'}.'('.$tmp->{'ID'}.')', 1);
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

	dolog($self,"db_read_lock() start");

	while (db_execute($self, 'FLUSH TABLES WITH READ LOCK', $self->{'dict'}->{'db'}->{'timeout'})) {
		dolog($self,"Trying to acquire read_lock...".$count);
		$count += 1;
		if ($count == $self->{'dict'}->{'db'}->{'maxretry'}) {
			if ($kill) {
				db_kill($self);
			}
			if ($fatal) {
				error($self,"Can't acquire the GLOBAL READ LOCK in time (timeout: $self->{'dict'}->{'db'}->{'timeout'}, maxretry: $self->{'dict'}->{'db'}->{'maxretry'})!");
			} else {
				return -1;
				last;
			}
		}
	} 
	dolog($self,"db_read_lock() end");
	return 0;
}

sub db_close {
	my $self = shift;

	dolog($self,"db_close() start");
	$self->{'dict'}->{'db'}->{'dbh'}->disconnect;
	dolog($self,"db_close() end");
}

sub REAPER {
	my $pid;

	$pid = waitpid(-1, &WNOHANG);

	if ($pid == -1) {
		# no child waiting. Ignore it.
	} elsif (WIFEXITED($?)) {
		dolog(undef,"Process $pid exited.");
	} else {
		dolog(undef,"False alarm on $pid.");
	}

	$SIG{CHLD} = \&REAPER; 
}

sub ssh_open_master {
	my $self = shift;

	dolog($self,"ssh_open_master() start");

	$SIG{CHLD} = \&REAPER;

	my $pid;
	unless ($pid = fork()) {
		open(STDOUT, '>', '/dev/null');
		open(STDERR, '>', '/dev/null');

		my $ssh_cmd = 'ssh -N -M -S '.$self->{'dict'}->{'ssh'}->{'socket'}.' -l '.$self->{'dict'}->{'ssh'}->{'user'}.' '.$self->{'dict'}->{'ssh'}->{'hostname'};
		dolog($self,"ssh_cmd: ".$ssh_cmd);
		exec($ssh_cmd);
		exit();
	}

	dolog($self,"ssh_open_master() end");
}

sub ssh_close_master {
	my $self = shift;

	open(STDOUT, '>', '/dev/null');
	open(STDERR, '>', '/dev/null');
	my $ssh_cmd = 'ssh -S '.$self->{'dict'}->{'ssh'}->{'socket'}.' -l '.$self->{'dict'}->{'ssh'}->{'user'}.' -O exit '.$self->{'dict'}->{'ssh'}->{'hostname'};
	dolog($self,"ssh_cmd: ".$ssh_cmd);
	system($ssh_cmd);
}

sub remote_execute {
	my $self = shift;
	my $cmd = shift;
	my @outlines;
	my @errlines;

	dolog($self,"remote_execute(".$cmd.") start");

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
		dolog($self,"ssh_cmd: ".$ssh_cmd);

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
		dolog($self,"STDOUT:\n".join(" ",@outlines));
		dolog($self,"STDERR:\n".join(" ",@errlines));

		alarm(0);
	};

	alarm(0);
	sigaction( SIGALRM, $oldaction );

	close(\*IN);
	close(\*OUT);
	close(\*ERR);

	if ( $@ =~ /timeout/) { 
		error($self,"Something is wrong. SSH execution timeout!");
	}

	if ( $rc != 0 ) { 
		warning($self,"Something is wrong. SSH execution return code is not 0! ($cmd)");
	}

	dolog($self,"remote_execute() end");
	return (\@outlines, \@errlines, $rc);
}

sub local_execute {
	my $self = shift;
	my $cmd = shift;

	my (@outlines, @errlines);

	dolog($self,"local_execute(".$cmd.") start");

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
		dolog($self,"local_cmd: ".$local_cmd);

		$pid = open3(*IN, *OUT, *ERR, $local_cmd);
		_autoflush(\*IN, 1);
		_autoflush(\*OUT, 1);
		_autoflush(\*ERR, 1);

		$SIG{CHLD} = \&REAPER;

		print IN $self->{'dict'}->{'sudo'}->{'password'}; 
		@outlines = <OUT>;
		@errlines = <ERR>;
		dolog($self,"STDOUT:\n".join(" ",@outlines));
		dolog($self,"STDERR:\n".join(" ",@errlines));

		alarm(0);
	};
	
	alarm(0);
	sigaction( SIGALRM, $oldaction );

	close(\*IN);
	close(\*OUT);
	close(\*ERR);

	if ( $@ =~ /timeout/) { 
		error($self,"Something is wrong. Local execution timeout!");
	}

	if ( $rc != 0 ) { 
		warning($self,"Something is wrong. Local execution return code is not 0($rc)! ($cmd)");
	}

	dolog($self,"local_execute() end");

	return (\@outlines, \@errlines, $rc);
}

sub cmd_execute {
	my $self = shift;
	my $cmd = shift;

	dolog($self,"cmd_execute(".$cmd.") start");

	my ($outlines, $errlines, $rc);

	if ($self->{'dict'}->{'ssh'}->{'location'} eq "LOCAL") {
		($outlines, $errlines, $rc) = local_execute($self, $cmd);
	} else {
		($outlines, $errlines, $rc) = remote_execute($self, $cmd);
	}

	dolog($self,"cmd_execute() end");
	return ($outlines, $errlines, $rc);
}

sub purge {
	my $self = shift;
	dolog($self,"purge() start");

	foreach my $tmp (@register) {
		ssh_close_master($tmp);
		db_close($tmp);
	}

	dolog($self,"purge() end");
}

sub db_get_replication_info {
	my $self = shift;

	my $dict;

	$self->dolog('db_get_replication_info() start.');
	$dict = $self->db_get_dict('SHOW SLAVE STATUS');
	$self->db_check_dict($dict->[0],'Slave_IO_Running', 'Yes');
	$self->db_check_dict($dict->[0],'Slave_SQL_Running', 'Yes');
	$self->db_check_dict($dict->[0],'Relay_Master_Log_File', $dict->[0]->{'Master_Log_File'});
	$self->db_check_dict($dict->[0],'Exec_Master_Log_Pos', $dict->[0]->{'Read_Master_Log_Pos'});

	$self->db_get_dict('SHOW MASTER STATUS');
	$self->db_get_dict('SHOW BINARY LOGS');
	$self->dolog('db_get_replication_info() end.');
}

sub db_check_replication_sync {
	my $self = shift;
	my $pnode = shift;
	my $lagretry = shift;
	my $lagsleep = shift;
	my $doit = shift;
	my $_RC = 0;

	my ($adict, $pdict);

	$self->dolog('db_get_replication_info() start.');

	$adict = $self->db_get_dict('SHOW SLAVE STATUS');
	$pdict = $pnode->db_get_dict('SHOW MASTER STATUS');

	$self->dolog('Checking replication threads', 1);

	$self->db_check_dict($adict->[0],'Slave_IO_Running', 'Yes', $doit);
	$self->db_check_dict($adict->[0],'Slave_SQL_Running', 'Yes', $doit);

	$self->dolog('Checking replication state...', 1);
	do {
		sleep($lagsleep);
		$_RC = 0;
		$_RC += $self->db_check_dict($adict->[0],'Relay_Master_Log_File', $adict->[0]->{'Master_Log_File'});
		$_RC += $self->db_check_dict($adict->[0],'Exec_Master_Log_Pos', $adict->[0]->{'Read_Master_Log_Pos'});
		$_RC += $self->db_check_dict($adict->[0],'Master_Log_File', $pdict->[0]->{'File'});
		$_RC += $self->db_check_dict($adict->[0],'Read_Master_Log_Pos', $pdict->[0]->{'Position'});
		$self->dolog("Rc: ".$_RC." Retry: ".$lagretry);
		$lagretry -= 1;
	} while(($_RC != 0) && ($lagretry != 0));

	if ($_RC && $doit ) {
		$_RC = 0;
		$_RC += $self->db_check_dict($adict->[0],'Relay_Master_Log_File', $adict->[0]->{'Master_Log_File'}, 1);
		$_RC += $self->db_check_dict($adict->[0],'Exec_Master_Log_Pos', $adict->[0]->{'Read_Master_Log_Pos'}, 1);
		$_RC += $self->db_check_dict($adict->[0],'Master_Log_File', $pdict->[0]->{'File'}, 1);
		$_RC += $self->db_check_dict($adict->[0],'Read_Master_Log_Pos', $pdict->[0]->{'Position'}, 1);
	}

	if ($_RC == 0) {
		$self->dolog('Replication state: Synched!', 1);
	}

	$self->dolog('db_get_replication_info() end.');
	return $_RC;
}

sub db_set_read_lock {
	my $self = shift;
	my $doit = shift;
	my $_RC = 0;

	$self->dolog('db_set_read_lock() start.');
	$self->dolog("Current threadid(active): ".$self->{'dict'}->{'db'}->{'dbh'}->{'mysql_thread_id'});
	$self->dolog('Trying to get read lock...', 1);
	if ($self->db_read_lock(0,1) != 0) {
		$_RC = $_RC+1;		
	}
	if ($doit) {
		$self->db_read_lock(1,0);
		$self->dolog('Read lock acquired!', 1);
	}
	$self->dolog('db_set_read_lock() end.');
	return $_RC;
}

sub db_set_passive {
	my $self = shift;
	my $doit = shift;
	my $_RC = 0;

	$self->dolog('db_set_passive() start.');
	if ($self->{'dict'}->{'db'}->{'type'} ne 'PASSIVE') {
		if ($doit) {
			$self->db_execute('set @@global.read_only=1', 1);
		}
		if ($self->db_get_dict('select @@global.read_only')->[0]->{'@@global.read_only'}) {
			$self->dolog('Read only mode has been set!', 1);
		} else {
			if ($doit) {
				$self->error('@@global.read_only == 1!');
			} else {
				$self->warning('@@global.read_only != 1!');
			}
			$_RC = $_RC+1;
		}
	}
	$self->dolog('db_set_passive() end.');
	return $_RC;
} 

sub db_set_active {
	my $self = shift;
	my $doit = shift;
	my $_RC = 0;

	$self->dolog('db_set_active() start.');
	if ($self->{'dict'}->{'db'}->{'type'} ne 'ACTIVE') {
		if ($doit) {
			$self->db_execute('set @@global.read_only=0', 1);
		}
		if ($self->db_get_dict('select @@global.read_only')->[0]->{'@@global.read_only'} == 0) {
			$self->dolog('Read/Write mode has been set!', 1);
		} else {
			if ($doit) {
				$self->error('@@global.read_only == 0!');
			} else {
				$self->warning('@@global.read_only != 0!');
			}
			$_RC = $_RC+1;
		}
	}
	$self->dolog('db_set_active() end.');
	return $_RC;
} 

sub nat_set {
	my $self = shift;
	my $virts = shift;
	my $doit = shift;
	my $_RC = 0;

	my ($outlines, $errlines, $rc);
	my $ips;
	$self->dolog('db_nat_set() start.');
	foreach my $tmp (sort keys %{$virts}) {
		($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/iptables -L -n -t nat');
		if ($rc != 0) {
			$_RC = $_RC+1;
			$self->error("Can't get iptables list!");
		}

		my $regex = $tmp.'\s+tcp\s+dpt:'.$virts->{$tmp}->{'port'}.'\s+redir\s+ports\s+'.$self->{'dict'}->{'db'}->{'port'};
		foreach my $ttmp (@{$outlines}) {
			if ($ttmp =~ /$regex/) {
				$ips->{$tmp} = 1;
			}
		}
	}

	foreach my $tmp (sort keys %{$virts}) {
		if (!defined($ips->{$tmp})) {
			my $message = 'NAT rule is missing: '.$tmp.':'.$virts->{$tmp}->{'port'}.'->'.$self->{'dict'}->{'db'}->{'port'};
			if ($doit) {
				($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/iptables -A PREROUTING -t nat -i '.$self->{'dict'}->{'db'}->{'virtif'}.' -p tcp --dst '.$tmp.' --dport '.$virts->{$tmp}->{'port'}.' -j REDIRECT --to-port '.$self->{'dict'}->{'db'}->{'port'});
				if ($rc != 0) {
					$_RC = $_RC+1;
					$self->warning($message." - iptables error!");
				} else {
					$self->dolog($message." - fixed", 1);
				}
			} else {
				$self->dolog($message." - dry run!", 1);
			}
		} else {
			$self->dolog('NAT rule is set: '.$tmp.':'.$virts->{$tmp}->{'port'}."->".$self->{'dict'}->{'db'}->{'port'}, 1);
		}
	}
	$self->dolog('db_nat_set() start.');
	return $_RC;
}
sub nat_unset {
	my $self = shift;
	my $virts = shift;
	my $doit = shift;
	my $_RC = 0;

	my ($outlines, $errlines, $rc);
	my $ips;
	$self->dolog('db_nat_unset() start.');
	foreach my $tmp (sort keys %{$virts}) {
		($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/iptables -L -n -t nat');
		if ($rc != 0) {
			$_RC = $_RC+1;
			$self->error("Can't get iptables list!");
		}

		my $regex = $tmp.'\s+tcp\s+dpt:'.$virts->{$tmp}->{'port'}.'\s+redir\s+ports\s+'.$self->{'dict'}->{'db'}->{'port'};
		foreach my $ttmp (@{$outlines}) {
			if ($ttmp =~ /$regex/) {
				$ips->{$tmp} = 1;
			}
		}
		if (!($ips->{$tmp})) {
			$self->dolog('NAT rule is not set: '.$tmp.':'.$virts->{$tmp}->{'port'}."->".$self->{'dict'}->{'db'}->{'port'}, 1);
		}
	}

	foreach my $tmp (sort keys %{$ips}) {
		$self->dolog('NAT rule is set: '.$tmp.':'.$virts->{$tmp}->{'port'}."->".$self->{'dict'}->{'db'}->{'port'}, 1);
		my $message = 'Unconfigure NAT: '.$tmp.':'.$virts->{$tmp}->{'port'}.'->'.$self->{'dict'}->{'db'}->{'port'};
		if ($doit) {
			($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/iptables -D PREROUTING -t nat -i '.$self->{'dict'}->{'db'}->{'virtif'}.' -p tcp --dst '.$tmp.' --dport '.$virts->{$tmp}->{'port'}.' -j REDIRECT --to-port '.$self->{'dict'}->{'db'}->{'port'});
			if ($rc != 0) {
				$_RC = $_RC+1;
				$self->warning($message." -  iptables error!");
			} else {
				$self->dolog($message." - fixed", 1);
			}
		} else {
			$self->dolog($message." - dry run!", 1);
		}
	}
	$self->dolog('db_nat_unset() end.');
	return $_RC;
}

sub vip_set {
	my $self = shift;
	my $virts = shift;
	my $doit = shift;
	my $_RC = 0;

	my ($outlines, $errlines, $rc);
	$self->dolog('db_vip_set() start.');
	($outlines, $errlines, $rc) = $self->cmd_execute("/sbin/ip addr list");
	if ($rc != 0) {
		$_RC = $_RC+1;
		$self->error("Can't get ip addr list!");
	}

	my $ips;
	foreach my $tmp (@{$outlines}) {
		if ($tmp =~ /inet\s(\S+)\s/) {
			my $ip = (split('/',$1))[0];
			$ips->{$ip} = 1;
		}
	}

	foreach my $tmp (sort keys %{$virts}) {
		if (!defined($ips->{$tmp})) {
			my $message = 'VIP is missing: '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.'->'.$self->{'dict'}->{'db'}->{'virtif'}.'->'.$self->{'dict'}->{'db'}->{'virtlabel'};
			if ($doit) {
				($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/ip addr add '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.' dev '.$self->{'dict'}->{'db'}->{'virtif'}.' label '.$self->{'dict'}->{'db'}->{'virtlabel'});
				if ($rc != 0) {
					$_RC = $_RC+1;
					$self->warning($message." - ip addr add error!");
				} else {
					$message .= " - ip addr add fixed";		
				}
				($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/arping -A -c 4 -I '.$self->{'dict'}->{'db'}->{'virtif'}.' '.$tmp);
				if ($rc != 0) {
					$_RC = $_RC+1;
					$self->warning($message." - arping error!");
				} else {
					$message .= " - arping fixed";
				}
				$self->dolog($message, 1);
			} else {
				$self->dolog($message." - dry run!", 1);
			}
		} else {
			$self->dolog('VIP is set: '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.'->'.$self->{'dict'}->{'db'}->{'virtif'}.'->'.$self->{'dict'}->{'db'}->{'virtlabel'}, 1);
		}
	}
	$self->dolog('db_vip_set() start.');
	return $_RC;
}

sub vip_unset {
	my $self = shift;
	my $virts = shift;
	my $doit = shift;
	my $_RC = 0;

	my ($outlines, $errlines, $rc);
	$self->dolog('db_vip_unset() start.');
	($outlines, $errlines, $rc) = $self->cmd_execute("/sbin/ip addr list");
	if ($rc != 0) {
		$_RC = $_RC+1;
		$self->error("Can't get ip addr list!");
	}

	my $ips;
	foreach my $tmp (@{$outlines}) {
		if ($tmp =~ /inet\s(\S+)\s/) {
			my $ip = (split('/',$1))[0];
			$ips->{$ip} = 1;
		}
	}

	foreach my $tmp (sort keys %{$virts}) {
		if (defined($ips->{$tmp})) {
			$self->dolog('VIP is set: '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.'->'.$self->{'dict'}->{'db'}->{'virtif'}.'->'.$self->{'dict'}->{'db'}->{'virtlabel'}, 1);
			my $message = 'Unconfigure VIP: '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.':'.$self->{'dict'}->{'db'}->{'virtif'}.':'.$self->{'dict'}->{'db'}->{'virtlabel'};
			if ($doit) {
				($outlines, $errlines, $rc) = $self->cmd_execute('/sbin/ip addr del '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.' dev '.$self->{'dict'}->{'db'}->{'virtif'}.' label '.$self->{'dict'}->{'db'}->{'virtlabel'});
				if ($rc != 0) {
					$_RC = $_RC+1;
					$self->warning($message." - ip addr del error!");
				} else {
					$self->dolog($message." - fixed", 1);
				}
			} else {
				$self->dolog($message." - dry run!", 1);
			}
		} else {
			$self->dolog('VIP is not set: '.$tmp.'/'.$virts->{$tmp}->{'netmask'}.'->'.$self->{'dict'}->{'db'}->{'virtif'}.'->'.$self->{'dict'}->{'db'}->{'virtlabel'}, 1);
		}
	}
	$self->dolog('db_vip_unset() end.');
	return $_RC;
}

1;
