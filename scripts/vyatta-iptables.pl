#!/usr/bin/perl -w
#
#
#
#
#

use strict;
use warnings;
use 5.010;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;

#
# Set to stop the actual execution of the commands..
#
my $DRY_RUN = 0;

#
# Global definitions...
#
my $valid_policy = { "ACCEPT" => 1, "DROP" => 1, "REJECT" => 1 };
my $sys_chains = {
		"filter" => { 
				"INPUT" => 1, 
				"FORWARD" => 1, 
				"OUTPUT" => 1 
		},
		"nat" => { 
				"PREROUTING" => 1, 
				"INPUT" => 1, 
				"OUTPUT" => 1, 
				"POSTROUTING" => 1 
		},
		"mangle" => { 
				"PREROUTING" => 1, 
				"INPUT" => 1, 
				"FORWARD" => 1, 
				"OUTPUT" => 1, 
				"POSTROUTING" => 1 
		},
		"raw" => { 
				"PREROUTING" => 1, 
				"OUTPUT" => 1 
		}
};

#
# /proc/sys/net options
#
my $psn_options = {
		"send-redirects" => { default => 1, enable => 1, disable => 0, 
						path => "/proc/sys/net/ipv4/conf/*/send_redirects" },
		"log-martians" => { default => 1, enable => 1, disable => 0, 
						path => "/proc/sys/net/ipv4/conf/*/log_martians" },
		"all-ping" => { default => 0, enable => 0, disable => 1, 
						path => "/proc/sys/net/ipv4/icmp_echo_ignore_all" },
		"broadcast-ping" => { default => 1, enable => 0, disable => 1,
						path => "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts" },
		"ip-src-route" => { default => 0, enable => 1, disable => 0,
						path => "/proc/sys/net/ipv4/conf/*/accept_source_route" },
		"receive-redirects" => { default => 0, enable => 1, disable => 0, 
						path => "/proc/sys/net/ipv4/conf/*/accept_redirects" },
		"source-validation" => { default => 0, strict => 1, loose => 2, disable => 0, 
						path => "/proc/sys/net/ipv4/conf/*/rp_filter" },
		"syn-cookies" => { default => 1, enable => 1, disable => 0, 
						path => "/proc/sys/net/ipv4/tcp_syncookies" }
};

sub validate_psn {
	my($option, $value) = @_;
	my %list = ();
	
	print STDERR "ValidatePSN: opt=$option val=$value\n";
	
	return 1 if(not defined $psn_options->{$option});
	my @opts = keys(%{$psn_options->{$option}});
	foreach my $o (@opts) {
		next if($o eq "default");
		next if($o eq "path");
		$list{$o} = 1;
	}
	if(not defined $list{$value}) {
		print STDERR "illegal value for $option, can be: " .
				join(", ", keys %list) . "\n";
		return 1;
	}
	return 0;
}

sub set_psn {
	my($option, $value) = @_;
	my $rc = 0;

	if(not defined $psn_options->{$option}) {
		print STDERR "unknown option: $option\n";
		return 1;
	}
	if(defined $value) {
		if(defined $psn_options->{$option}->{$value}) {
			$value = $psn_options->{$option}->{$value};
		} else {
			$value = undef;
		}
	}
	$value = $psn_options->{$option}->{"default"} if not defined $value;
	my @paths = glob($psn_options->{$option}->{"path"});

	foreach my $path (@paths) {
		$rc += cmd("echo ${value} > ${path}");
	}
	return 1 if $rc;
	return 0;
}


#
# Execute (or print) a given command and check the return status
# for failure
#
sub cmd {
	my($cmd) = @_;

	if($DRY_RUN) {
		print "> $cmd\n";
		return 0;
	}
	system($cmd);
	if($? == -1) {
		print STDERR "ERROR: failed to run command: $cmd\n";
		return 1;
	}
	return $? >> 8;
}

#
# Main init routine for when this module is started (or created), we just
# do the standard stuff that the default firewall module did, except we
# don't do anything to the rules, that will happen later.
#
sub iptables_init {
	my $fail = 0;
	my @modules = ( "nf_conntrack", "nf_contrack_ftp", "nf_contrack_tftp",
		"nf_nat", "nf_nat_ftp", "nf_nat_tftp", "nf_nat_proto_gre", 
		"nf_nat_sip", "nf_nat_h323", "nf_nat_pptp" );
	my %sysctl = (
		"net.netfilter.nf_conntrack_tcp_be_liberal" => 1,
		"net.nf_conntrack_max" => 16384,
		"net.netfilter.nf_conntrack_expect_max" => 2048,
		"net.netfilter.nf_conntrack_tcp_timeout_established" => 7200 );

	#
	# Load all the modules...
	#
	foreach my $module (@modules) {
		$fail += cmd("modprobe --syslog ${module}");
	}
	
	#
	# Change sysctl settings...
	#
	foreach my $param (keys %sysctl) {
		my $value = $sysctl{$param};
		$fail += cmd("sysctl -q -w ${param}=${value}");
	}
	
	#
	# Initialise the tables...
	#
	foreach my $table (keys %{$sys_chains}) {
		$fail += cmd("iptables -t ${table} -F");
		$fail += cmd("iptables -t ${table} -X");
	}
	
	return 1 if $fail;
	return 0;
}

#
# Check table/chain/policy for two things:
#
# 1. Is this a valid table/chain to set a policy on
# 2. Is the policy a valid type
#
# If the base node (table) isn't setup then we won't get
# the table name, so we have to suggest creating the base node
# first.
#
sub validate_policy {
	my($table, $chain, $policy) = @_;

	if($table eq "") {
		print STDERR "the table is not yet setup, unable to set policy.\n";
		return 1;
	}
	if(not defined $sys_chains->{$table}->{$chain}) { 
		print STDERR "policy can not be set on ${table}/${chain}\n";
		return 1;
	}
	if(not defined $valid_policy->{$policy}) {
		print STDERR "policy must be one of: " . join(", ", keys %{$valid_policy}) . "\n";
		return 1;
	}
	return 0;
}

#
# Check if the table/chain is a system chain
#
sub validate_protected_update {
	my($table, $chain, $value) = @_;
		
	if(not defined $sys_chains->{$table}->{$chain}) {
		print STDERR "protected-update can not be set on ${table}/${chain}\n";
		return 1;
	}
	if($value ne "enable" && $value ne "disable") {
		print STDERR "protected-update should be enable or disable\n";
		return 1;
	}
	return 0;
}

#
# Load variables ... read all the variables into a hash of arrays
#
sub load_variables {
	my($cf) = @_;
	my %rc = ();

	my @vars = $cf->listNodes("variable");
	foreach my $var (@vars) {
		@{$rc{$var}} = $cf->returnValues("variable ${var} value");
	}
	return %rc;
}

#
# Preprocess the rules list, this will simply expand any variables.
#
# For the variables... we'll loop round and keep re-evaluating until we
# know we have processed everything, so we should cope with multiple
# list type variables and it will expand into a x*y type.
#
sub preprocess {
	my($vars) = shift @_;
	my(@in) = @_;
	my @out = ();
	
	while(@in) {
		my $r = shift @in;
		
		if($r =~ /\[([^\]]+)\]/) {
			my($v) = $1;
			if($vars->{$v}) {
				foreach my $rv (@{$vars->{$v}}) {
					my $new_r = $r;
					$new_r =~ s/\[$v\]/$rv/g;
					unshift @in, $new_r;
				}
			} else {
				print STDERR "Undefined variable [$v] in iptables rule, excluding:\n";
				print STDERR "\t$r\n";
			}
		} else { push @out, $r; }
	}
	return @out;
}

#
# Look at a set of rules and see if we can find jumps (-j) to other
# known chains that we haven't processed yet, we'll return a 1
# if we have something incomplete, so we can delay processing.
#
sub has_incomplete_subchains {
	my($chain_names, @rules) = @_;
	my @rc = ();
        
	foreach my $rule (@rules) {
		my $target;
		if($rule =~ /-j\s+([^\s]+)/) {
			$target = $1;
			return 1 if(defined $chain_names->{$target} && $chain_names->{$target} == 0);
		}
	}
	return 0;
}

#
# Process a chain, we know that there are no unresolved references to
# other chains, so this should just work (other than syntax problems)
#
sub process_chain {
	my($table, $chain, $policy, $protection, @rules) = @_;
	my $rc = 0;
	
	if(not defined $sys_chains->{$table}->{$chain}) {
		$rc += cmd("iptables -t $table -N $chain");
	}
    
	foreach(@rules) {
		$rc += cmd("iptables -t $table -A $chain $_");
	}
	#
	# Set the final policy...
	#
	if(defined $sys_chains->{$table}->{$chain}) {
		$policy = "ACCEPT" if(not defined $policy);
		$rc += cmd("iptables -t $table -P $chain $policy");
	}
	return 1 if $rc;
	return 0;
}

#
# Build a rules list for a given chain, this can be quite slow so we should
# cache the results
#
# Returns a reference to the list
#
#
# TODO: build a cache into this mechanism
#
sub build_rules_list {
	my($cf, $table, $chain) = @_;
	state %rules_cache;
	
	if(not defined $rules_cache{"$table/$chain"}) {
		my @rules = ();
		my @nos = $cf->listNodes("${table} chain ${chain} rule");
		foreach my $n (@nos) {
			my $rule = $cf->returnValue("${table} chain ${chain} rule ${n} exec");
			push @rules, $rule if(defined $rule);
		}
		$rules_cache{"$table/$chain"} = \@rules;
		return \@rules;
	}
	return $rules_cache{"$table/$chain"};
}

#
# Find all the tables that make use of a given variable and return the list
#
sub find_variable_usage {
	my($cf, $var) = @_;
	my @rc = ();
	
	foreach my $table (keys %{$sys_chains}) {
		foreach my $chain ($cf->listNodes("${table} chain")) {
			my @rules = @{ build_rules_list($cf, $table, $chain) };
			if(grep(/\[${var}\]/, @rules)) {
				push @rc, $table;
			}
		}
	}
	return @rc;
}

#
# Find and return all the tables/chains that reference a given ipset
#
# we look for "-m set" and then either "--set <name>" or "--match-set <name>"
#
sub find_ipset_usage {
	my($cf, $ipset) = @_;
	my %rc = ();
	
	foreach my $table (keys %{$sys_chains}) {
		foreach my $chain ($cf->listNodes("${table} chain")) {
			my @rules = @{ build_rules_list($cf, $table, $chain) };
			if(grep(/-m\s+set/ && (/--set\s+${ipset}\b/ || /--match-set\s+${ipset}\b/), @rules)) {
				$rc{"${table}/${chain}"} = 1;
			}
		}
	}
	return %rc;
}

#
# Process a table .. go through all the chains for a given table and install them
# in the correct order.
#
sub process_table {
	my($cf, $table, $vars) = @_;
	
	#
	# First we build a hash of the chains we will need to process...
	#
	my @chains = $cf->listNodes("${table} chain");

	return 0 if($#chains == -1);	
	
	my %chain_done = ();
	my $work_to_do = 1;	# first loop is forced
	my $work_done;
	my $rc = 0;
	foreach(@chains) { $chain_done{$_} = 0; }
	
	#	
	# Repeatedly loop through all the chains, deferring any that have
	# unprocessed references. That way all the sub-chains will be completed
	# first, before the calling chains. So the dependencies will work themselves
	# out. We'll also detect loops here.
	#
	while($work_to_do) {
		$work_to_do = 0;
		foreach my $chain (@chains) {
			next if($chain_done{$chain});
		
			my $rules = build_rules_list($cf, $table, $chain);
			if(has_incomplete_subchains(\%chain_done, @{$rules})) {
				$work_to_do = 1;
				next;
			}
			my $policy = undef;
			if(defined $sys_chains->{$table}->{$chain}) {
				$policy = $cf->returnValue("${table} chain ${chain} policy");
			}
			my $protection = $cf->returnValue("${table} chain ${chain} protected-update");
			$rc += process_chain($table, $chain, $policy, $protection, preprocess($vars, @{$rules}));
			$chain_done{$chain} = 1;
			$work_done++;
		}
		if($work_done == 0) {
			print STDERR "ERROR: loop detected in table ${table} - unable to complete.\n";
			$rc++;
			last;
		}
	}
	return $rc;
}

#
# Prepare a table for recreating ... we go through each system chain setting
# policy to ACCEPT if protection is configured. Then we flush and delete
# everything.
#
sub prepare_table {
	my($cf, $table) = @_;
	my $rc = 0;
	
	foreach my $chain (keys %{$sys_chains->{$table}}) {
		my $protection = $cf->returnValue("${table} chain ${chain} protected-update");
		if(defined $protection && $protection eq "enable") {
			$rc += cmd("iptables -t ${table} -P ${chain} ACCEPT");
		}
	}
	$rc += cmd("iptables -t ${table} -F");
	$rc += cmd("iptables -t ${table} -X");

	return 1 if $rc;	
	return 0;
}

#
# ipset routines....
#

sub ipset_delete {
	my($cf, $ipset) = @_;
	my $rc = cmd("ipset list ${ipset} >/dev/null 2>&1");
	return if($rc != 0);

	return cmd("ipset destroy ${ipset}");
}
sub ipset_create {
	my($cf, $ipset) = @_;
	my $type = $cf->returnValue("ipset ${ipset} type");
	my $rc;
	
	$rc = cmd("ipset list ${ipset} >/dev/null 2>&1");
	if($rc != 0) {
		$rc = cmd("ipset create ${ipset} ${type}");
		return 1 if $rc;
	}
	return ipset_update($cf, $ipset, 1);
}
sub ipset_update {
	my($cf, $ipset, $newflag) = @_;
	my %current = ();
	my $rc = 0;
	
	#
	# Delete anything we have removed...
	#
	foreach my $d ($cf->returnDeletedValues("ipset ${ipset} item")) {
		$rc += cmd("ipset -! del ${ipset} ${d}");
	}
	
	#
	# Build a list of current contents (based on config, not list)
	#
	if(not $newflag) {
		foreach my $i ($cf->returnOrigValues("ipset ${ipset} item")) { 
			$current{$i} = 1;
		}
	}
	
	#
	# Now work out which ones to really add
	#
	foreach my $a ($cf->returnValues("ipset ${ipset} item")) {
		if(not defined $current{$a}) {
			$rc += cmd("ipset -! add ${ipset} ${a}");
		}
	}
	return 1 if $rc;
	return 0;
}

# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================

# ------------------------------------------------------------------------------
# We use this script to validate some arguments, so we check the first argument
# to determin what action to take
# ------------------------------------------------------------------------------

my $cmd = shift @ARGV;

if(not defined $cmd) {
	print STDERR "missing command argument\n";
	exit 1;
}	

exit(validate_policy(@ARGV)) if($cmd eq "validate_policy");
exit(validate_protected_update(@ARGV)) if($cmd eq "validate_protected_update");
exit(validate_psn(@ARGV)) if($cmd eq "validate_psn");

if($cmd ne "commit" && $cmd ne "init" && $cmd ne "load") {
	print STDERR "$0: unknown request: $cmd\n";
	exit 1;
}

# ------------------------------------------------------------------------------
# Main process...
# ------------------------------------------------------------------------------

my $cf = new Vyatta::Config();
my %tables_to_update = ();
my $fail = 0;

# ------------------------------------------------------------------------------
# Before we can do anything we need to look to see if the filewall, port-forward
# or zone-policy have any configs. If they do, then we print a warning and do
# nothing, since we don't want to conflict.
#
# We will not fail here though, so that we can commit the config.
# ------------------------------------------------------------------------------

for my $system ("firewall", "port-forward", "zone-policy", "service webproxy",
				"system conntrack", "service nat") {
	if($cf->listNodes($system)) {
		print STDERR "WARNING: ${system} is configured.\n";
		$fail = 1;
	}
}
if($fail) {
	print STDERR "WARNING: iptables/ipsets will not be enabled.\n";
	exit 0;
}

# ------------------------------------------------------------------------------
# Check for other post-conflict options...
# ------------------------------------------------------------------------------

exit(iptables_init(@ARGV)) if($cmd eq "init");

# ------------------------------------------------------------------------------
# STEP 1: Check that any deleted ipsets are not being used
# ------------------------------------------------------------------------------

$cf->setLevel("iptables");
my %ipset_status = $cf->listNodeStatus("ipset");
foreach my $ipset (keys %ipset_status) {
	if($ipset_status{$ipset} eq "deleted") {
		my %refs = find_ipset_usage($cf, $ipset);
		if(scalar keys %refs) {
			print STDERR "unable to delete ipset ${ipset}, used in: " .
					join(", ", keys %refs) . "\n";
			$fail = 1;
		}
	}
}
exit 1 if $fail;

# ------------------------------------------------------------------------------
# STEP 2: Handle the options (/proc/sys/net)
# ------------------------------------------------------------------------------

my %option_status = $cf->listNodeStatus("option");
foreach my $option (keys %option_status) {
	if($option_status{$option} eq "deleted") {
		# Set to default...
		$fail += set_psn($option, undef);
	} elsif($option_status{$option} ne "static") {
		# A change or an add, means use the given value
		my $value = $cf->returnValue("option ${option}");
		$fail += set_psn($option, $value);
	}
}
exit 1 if $fail;

# ------------------------------------------------------------------------------
# STEP 2: Do the ipset adds, deletes and changes
# ------------------------------------------------------------------------------

foreach my $ipset (keys %ipset_status) {
	if($ipset_status{$ipset} eq "added") {
		$fail = ipset_create($cf, $ipset);
	} elsif($ipset_status{$ipset} eq "deleted") {
		$fail = ipset_delete($cf, $ipset);
	} elsif($ipset_status{$ipset} eq "changed") {
		$fail = ipset_update($cf, $ipset, 0);
	}
	last if $fail;
}
exit 1 if $fail;

# ------------------------------------------------------------------------------
# STEP 3: Work out what tables have been altered by looking at the chain
#         and policy nodes
# ------------------------------------------------------------------------------


foreach my $table (keys %{$sys_chains}) {
	my %status = $cf->listNodeStatus("${table}");
	if(defined $status{"chain"} && $status{"chain"} ne "static") {
		$tables_to_update{$table} = 1;
	}
	if(defined $status{"policy"} && $status{"policy"} ne "static") {
		$tables_to_update{$table} = 1;
	}
}

# ------------------------------------------------------------------------------
# STEP 4: Look at any changed variables and see if those variables are used
#         in any tables, if they are we mark them to be rebuilt.
# ------------------------------------------------------------------------------

my %var_status = $cf->listNodeStatus("variable");
foreach my $var (keys %var_status) {
	if($var_status{$var} ne "static") {
		foreach my $table (find_variable_usage($cf, $var)) {
			$tables_to_update{$table} = 1;
		}
	}
}

# ------------------------------------------------------------------------------
# If we specify "load" then we will force all the tables to load
# ------------------------------------------------------------------------------

if($cmd eq "load") {
	foreach my $table (keys %{$sys_chains}) {
		$tables_to_update{$table} = 1;
	}
}

# ------------------------------------------------------------------------------
# STEP 5: Prepare any tables we are going to rebuild, this means clearing
#         them, but also looking at protected updates.
# ------------------------------------------------------------------------------

foreach my $table (keys %tables_to_update) {
	$fail = prepare_table($cf, $table);
	last if $fail;
}
exit 1 if $fail;

# ------------------------------------------------------------------------------
# STEP 6: Actually rebuild the tables
# ------------------------------------------------------------------------------

my %vars = load_variables($cf);
foreach my $table (keys %tables_to_update) {
	$fail += process_table($cf, $table, \%vars);
}
exit 1 if $fail;
exit 0;

