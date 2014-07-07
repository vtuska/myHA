#!/usr/bin/perl -w

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

my $cfg = {
		'service' => {
			'virtip' => '172.16.72.100',
			'virtnet' => '24',
			'lagretry' => 3,
			'lagsleep' => 2
		},
		nodes => [
			{
				'db' => {
					'hostname' => '172.16.72.136',
					'port' => 3306,
					'user' => 'root',
					'password' => '',
					'database' => 'mysql',
					'timeout' => 2,
					'maxretry' => 3,
					'virtif' => 'eth0'
				},
				'ssh' => {
					'user' => 'viktor',
					'hostname' => '172.16.72.136',
					'timeout' => 24,
					'socket' => '~/.ssh/master0.sock'
				},
				'sudo' => {
					'password' => undef
				}
			},
			{
				'db' => {
					'hostname' => '172.16.72.137',
					'port' => 4204,
					'user' => 'root',
					'password' => '',
					'database' => 'mysql',
					'timeout' => 2,
					'maxretry' => 3,
					'virtif' => 'eth0',
					'virtport' => 3306
				},
				'ssh' => {
					'user' => 'viktor',
					'hostname' => '172.16.72.137',
					'timeout' => 24,
					'socket' => '~/.ssh/master1.sock'
				},
				'sudo' => {
					'password' => undef
				}
			},
		]
};

sub get_config {
	return $cfg;
}

1;
