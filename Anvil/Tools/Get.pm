package Anvil::Tools::Get;
# 
# This module contains methods used to handle access to frequently used data.
# 

use strict;
use warnings;
use Scalar::Util qw(weaken isweak);
use Data::Dumper;
use Encode;
use UUID::Tiny qw(:std);
use Net::Netmask;

our $VERSION  = "3.0.0";
my $THIS_FILE = "Get.pm";

### Methods;
# anvil_version
# cgi
# date_and_time
# host_uuid
# md5sum
# network
# network_details
# switches
# users_home
# uuid
# _salt
# _wrap_to

=pod

=encoding utf8

=head1 NAME

Anvil::Tools::Get

Provides all methods related to getting access to frequently used data.

=head1 SYNOPSIS

 use Anvil::Tools;

 # Get a common object handle on all Anvil::Tools modules.
 my $anvil = Anvil::Tools->new();
 
 # Access to methods using '$anvil->Get->X'. 
 # 
 # Example using 'date_and_time()';
 my $date = $anvil->Get->date_and_time({...});

=head1 METHODS

Methods in this module;

=cut
sub new
{
	my $class = shift;
	my $self  = {
		HOST	=>	{
			UUID	=>	"",
		},
	};
	
	bless $self, $class;
	
	return ($self);
}

# Get a handle on the Anvil::Tools object. I know that technically that is a sibling module, but it makes more 
# sense in this case to think of it as a parent.
sub parent
{
	my $self   = shift;
	my $parent = shift;
	
	$self->{HANDLE}{TOOLS} = $parent if $parent;
	
	# Defend against memory leads. See Scalar::Util'.
	if (not isweak($self->{HANDLE}{TOOLS}))
	{
		weaken($self->{HANDLE}{TOOLS});;
	}
	
	return ($self->{HANDLE}{TOOLS});
}


#############################################################################################################
# Public methods                                                                                            #
#############################################################################################################

=head2 anvil_version

This reads to C<< VERSION >> file of a local or remote machine. If the version file isn't found, C<< 0 >> is returned. 

Parameters;

=head3 password (optional)

This is the password to use when connecting to a remote machine. If not set, but C<< target >> is, an attempt to connect without a password will be made.

=head3 port (optional)

This is the TCP port to use when connecting to a remote machine. If not set, but C<< target >> is, C<< 22 >> will be used.

=head3 remote_user (optional, default root)

If C<< target >> is set, this will be the user we connect to the remote machine as.

=head3 target (optional)

This is the IP or host name of the machine to read the version of. If this is not set, the local system's version is checked.

=cut
# NOTE: the version is set in anvil.spec by sed'ing the release and arch onto anvil.version in anvil-core's %post
sub anvil_version
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $password    = defined $parameter->{password}    ? $parameter->{password}    : "";
	my $port        = defined $parameter->{port}        ? $parameter->{port}        : "";
	my $remote_user = defined $parameter->{remote_user} ? $parameter->{remote_user} : "root";
	my $target      = defined $parameter->{target}      ? $parameter->{target}      : "local";
	my $version     = 0;
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 
		password    => $anvil->Log->secure ? $password : $anvil->Words->string({key => "log_0186"}),
		port        => $port, 
		remote_user => $remote_user, 
		target      => $target, 
	}});
	
	# Is this a local call or a remote call?
	if (($target) && ($target ne "local") && ($target ne $anvil->_hostname) && ($target ne $anvil->_short_hostname))
	{
		# Remote call.
		my $shell_call = "
if [ -e ".$anvil->data->{path}{configs}{'anvil.version'}." ];
then
    cat ".$anvil->data->{path}{configs}{'anvil.version'}.";
else
   echo 0;
fi;
";
		$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => $debug, key => "log_0166", variables => { shell_call => $shell_call, target => $target, remote_user => $remote_user }});
		my ($error, $output) = $anvil->Remote->call({
			debug       => $debug, 
			shell_call  => $shell_call, 
			target      => $target,
			port        => $port, 
			password    => $password,
			remote_user => $remote_user, 
		});
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { error => $error }});
		
		$version = defined $output->[0] ? $output->[0] : "";
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { version => $version }});
	}
	else
	{
		# Local.
		$version = $anvil->Storage->read_file({file => $anvil->data->{path}{configs}{'anvil.version'}});
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { version => $version }});
		
		# Did we actually read a version?
		if ($version eq "!!error!!")
		{
			$version = 0;
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => 1, list => { version => $version }});
		}
	}
	
	# Clear off any newline.
	$version =~ s/\n//gs;
	
	return($version);
}

=head2 cgi

This reads in the CGI variables passed in by a form or URL.

This will read the 'cgi_list' CGI variable for a comma-separated list of CGI variables to read in. So your form must set this in order for this method to work.

If the variable 'file' is passed, it will be treated as a binary stream containing an uploaded file.

=cut
sub cgi
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	# This will store all of the CGI variables.
	$anvil->data->{sys}{cgi_string} = "?";
	
	# Needed to read in passed CGI variables
	my $cgi = CGI->new();
	
	# The list of CGI variables to try and read will always be in 'cgi_list'.
	my $cgis      = [];
	my $cgi_count = 0;
	if (defined $cgi->param("cgi_list"))
	{
		my $cgi_list = $cgi->param("cgi_list");
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { cgi_list => $cgi_list }});
		
		foreach my $variable (split/,/, $cgi_list)
		{
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { variable => $variable }});
			push @{$cgis}, $variable;
		}
	}
	elsif (exists $cgi->{param})
	{
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 'cgi->{param}' => $cgi->{param} }});
		foreach my $variable (sort {$a cmp $b} keys %{$cgi->{param}})
		{
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { variable => $variable }});
			push @{$cgis}, $variable;
		}
	}
	
	$cgi_count = @{$cgis};
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { cgi_count => $cgi_count }});
	
	# If we don't have at least one variable, we're done.
	if ($cgi_count < 1)
	{
		return(0);
	}
	
	# NOTE: Later, we will have another array for handling file uploads.
	# Now read in the variables.
	foreach my $variable (sort {$a cmp $b} @{$cgis})
	{
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { variable => $variable }});
		
		$anvil->data->{cgi}{$variable}{value}      = "";
		$anvil->data->{cgi}{$variable}{mimetype}   = "string";
		$anvil->data->{cgi}{$variable}{filehandle} = "";
		$anvil->data->{cgi}{$variable}{alert}      = 0;	# This is set if a sanity check fails
		
		if ($variable eq "file")
		{
			if (not $cgi->upload($variable))
			{
				# Empty file passed, looks like the user forgot to select a file to upload.
				#$anvil->Log->entry({log_level => $debug, message_key => "log_0016", file => $THIS_FILE, line => __LINE__});
			}
			else
			{
				   $anvil->data->{cgi}{$variable}{filehandle} = $cgi->upload($variable);
				my $file                                      = $anvil->data->{cgi}{$variable}{filehandle};
				   $anvil->data->{cgi}{$variable}{mimetype}   = $cgi->uploadInfo($file)->{'Content-Type'};
				$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 
					variable                       => $variable,
					"cgi::${variable}::filehandle" => $anvil->data->{cgi}{$variable}{filehandle},
					"cgi::${variable}::mimetype"   => $anvil->data->{cgi}{$variable}{mimetype},
				}});
			}
		}
		
		if (defined $cgi->param($variable))
		{
			# Make this UTF8 if it isn't already.
			if (Encode::is_utf8($cgi->param($variable)))
			{
				$anvil->data->{cgi}{$variable}{value} = $cgi->param($variable);
				$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "cgi::${variable}::value" => $anvil->data->{cgi}{$variable}{value} }});
			}
			else
			{
				$anvil->data->{cgi}{$variable}{value} = Encode::decode_utf8($cgi->param($variable));
				$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "cgi::${variable}::value" => $anvil->data->{cgi}{$variable}{value} }});
			}
			
			# Append to 'sys::cgi_string'
			$anvil->data->{sys}{cgi_string} .= "$variable=".$anvil->data->{cgi}{$variable}{value}."&";
		}
	}
	
	# This is a pretty way of displaying the passed-in CGI variables. It loops through all we've got and
	# sorts out the longest variable name. Then it loops again, appending '.' to shorter ones so that 
	# everything is lined up in the logs. This almost always prints, save for log level 0.
	if ($anvil->Log->level >= 1)
	{
		my $longest_variable = 0;
		foreach my $variable (sort {$a cmp $b} keys %{$anvil->data->{cgi}})
		{
			next if $anvil->data->{cgi}{$variable} eq "";
			if (length($variable) > $longest_variable)
			{
				$longest_variable = length($variable);
			}
		}
		
		# Now loop again in the order that the variables were passed is 'cgi_list'.
		foreach my $variable (@{$cgis})
		{
			next if $anvil->data->{cgi}{$variable} eq "";
			my $difference   = $longest_variable - length($variable);
			my $say_value    = "value";
			if ($difference == 0)
			{
				# Do nothing
			}
			elsif ($difference == 1) 
			{
				$say_value .= " ";
			}
			elsif ($difference == 2) 
			{
				$say_value .= "  ";
			}
			else
			{
				my $dots      =  $difference - 2;
				   $say_value .= " ";
				for (1 .. $dots)
				{
					$say_value .= ".";
				}
				$say_value .= " ";
			}
			# This is always '1' as the passed-in variables are what we want to see.
			my $censored_value = $anvil->data->{cgi}{$variable}{value};
			if ((($variable =~ /passwd/) or ($variable =~ /password/)) && (not $anvil->Log->secure))
			{
				# This is a password and we're not logging sensitive data, obfuscate it.
				$censored_value = $anvil->Words->string({key => "log_0186"});
			}
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 
				"cgi::${variable}::$say_value" => $censored_value,
			}});
		}
	}
	
	# Clear the last &
	$anvil->data->{sys}{cgi_string} =~ s/&$//;
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "sys::cgi_string" => $anvil->data->{sys}{cgi_string} }});
	
	return(0);
}

=head2 date_and_time

This method returns the date and/or time using either the current time, or a specified unix time.

NOTE: This only returns times in 24-hour notation.

=head2 Parameters;

=head3 date_only (optional)

If set, only the date will be returned (in C<< yyyy/mm/dd >> format).

=head3 file_name (optional)

When set, the date and/or time returned in a string more useful in file names. Specifically, it will replace spaces with 'C<< _ >>' and 'C<< : >>' and 'C<< / >>' for 'C<< - >>'. This will result in a string in the format like 'C<< yyyy-mm-dd_hh-mm-ss >>'.

=head3 offset (optional)

If set to a signed number, it will add or subtract the number of seconds from the 'C<< use_time >>' before processing.

=head3 use_time (optional)

This can be set to a unix timestamp. If it is not set, the current time is used.

=head3 time_only (optional)

If set, only the time will be returned (in C<< hh:mm:ss >> format).

=cut
sub date_and_time
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $offset    = defined $parameter->{offset}    ? $parameter->{offset}    : 0;
	my $use_time  = defined $parameter->{use_time}  ? $parameter->{use_time}  : time;
	my $file_name = defined $parameter->{file_name} ? $parameter->{file_name} : 0;
	my $time_only = defined $parameter->{time_only} ? $parameter->{time_only} : 0;
	my $date_only = defined $parameter->{date_only} ? $parameter->{date_only} : 0;
	
	### NOTE: This is used too early for normal error handling.
	# Are things sane?
	if ($use_time =~ /D/)
	{
		die "Get->date_and_time() was called with 'use_time' set to: [$use_time]. Only a unix timestamp is allowed.\n";
	}
	if ($offset =~ /D/)
	{
		die "Get->date_and_time() was called with 'offset' set to: [$offset]. Only real number is allowed.\n";
	}
	
	# Do my initial calculation.
	my $return_string = "";
	my $time          = {};
	my $adjusted_time = $use_time + $offset;
	#print $THIS_FILE." ".__LINE__."; [ Debug ] - adjusted_time: [$adjusted_time]\n";
	
	# Get the date and time pieces
	($time->{sec}, $time->{min}, $time->{hour}, $time->{mday}, $time->{mon}, $time->{year}, $time->{wday}, $time->{yday}, $time->{isdst}) = localtime($adjusted_time);
	#print $THIS_FILE." ".__LINE__."; [ Debug ] - time->{sec}: [".$time->{sec}."], time->{min}: [".$time->{min}."], time->{hour}: [".$time->{hour}."], time->{mday}: [".$time->{mday}."], time->{mon}: [".$time->{mon}."], time->{year}: [".$time->{year}."], time->{wday}: [".$time->{wday}."], time->{yday}: [".$time->{yday}."], time->{isdst}: [".$time->{isdst}."]\n";
	
	# Process the raw data
	$time->{pad_hour} = sprintf("%02d", $time->{hour});
	$time->{mon}++;
	$time->{pad_min}  = sprintf("%02d", $time->{min});
	$time->{pad_sec}  = sprintf("%02d", $time->{sec});
	$time->{year}     = ($time->{year} + 1900);
	$time->{pad_mon}  = sprintf("%02d", $time->{mon});
	$time->{pad_mday} = sprintf("%02d", $time->{mday});
	#print $THIS_FILE." ".__LINE__."; [ Debug ] - time->{pad_hour}: [".$time->{pad_hour}."], time->{pad_min}: [".$time->{pad_min}."], time->{pad_sec}: [".$time->{pad_sec}."], time->{year}: [".$time->{year}."], time->{pad_mon}: [".$time->{pad_mon}."], time->{pad_mday}: [".$time->{pad_mday}."], time->{mon}: [".$time->{mon}."]\n";
	
	# Now, the date and time separator depends on if 'file_name' is set.
	my $date_separator  = $file_name ? "-" : "/";
	my $time_separator  = $file_name ? "-" : ":";
	my $space_separator = $file_name ? "_" : " ";
	if ($time_only)
	{
		$return_string = $time->{pad_hour}.$time_separator.$time->{pad_min}.$time_separator.$time->{pad_sec};
		#print $THIS_FILE." ".__LINE__."; [ Debug ] - return_string: [$return_string]\n";
	}
	elsif ($date_only)
	{
		$return_string = $time->{year}.$date_separator.$time->{pad_mon}.$date_separator.$time->{pad_mday};
		#print $THIS_FILE." ".__LINE__."; [ Debug ] - return_string: [$return_string]\n";
	}
	else
	{
		$return_string = $time->{year}.$date_separator.$time->{pad_mon}.$date_separator.$time->{pad_mday}.$space_separator.$time->{pad_hour}.$time_separator.$time->{pad_min}.$time_separator.$time->{pad_sec};
		#print $THIS_FILE." ".__LINE__."; [ Debug ] - return_string: [$return_string]\n";
	}
	
	return($return_string);
}

=head2 host_name

This takes a host UUID and returns the host name (as recorded in the C<< hosts >> table). If the entry is not found, an empty string is returned.

Parameters;

=head3 host_uuid (required)

This is the C<< host_uuid >> to translate into a host name.

=cut
sub host_name
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $host_name = "";
	my $host_uuid = defined $parameter->{host_uuid} ? $parameter->{host_uuid} : "";
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { host_uuid => $host_uuid }});
	
	my $query = "
SELECT 
    host_name 
FROM 
    hosts 
WHERE 
    host_uuid = ".$anvil->data->{sys}{database}{use_handle}->quote($host_uuid).";
";
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { query => $query }});
	my $results = $anvil->Database->query({query => $query, source => $THIS_FILE, line => __LINE__});
	my $count   = @{$results};
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 
		results => $results, 
		count   => $count, 
	}});
	if ($count == 1)
	{
		# Found it
		$host_name = defined $results->[0]->[0] ? $results->[0]->[0] : "";
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { host_name => $host_name }});
	}
	
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { host_name => $host_name }});
	return($host_name);
}

=head2 host_uuid

This returns the local host's system UUID (as reported by 'dmidecode'). If the host UUID isn't available, and the program is not running with root priviledges, C<< #!error!# >> is returned.

 print "This host's UUID: [".$anvil->Get->host_uuid."]\n";

It is possible to override the local UUID, though it is not recommended.

 $anvil->Get->host_uuid({set => "720a0509-533d-406b-8fc1-03aca3e75fa7"})

=cut
sub host_uuid
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $set = defined $parameter->{set} ? $parameter->{set} : "";
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { set => $set }});
	
	if ($set)
	{
		$anvil->data->{HOST}{UUID} = $set;
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "HOST::UUID" => $anvil->data->{HOST}{UUID} }});
	}
	elsif (not $anvil->data->{HOST}{UUID})
	{
		# Read dmidecode if I am root, otherwise, read the cache.
		my $uuid = "";
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { '$<' => $<, '$>' => $> }});
		if (($< == 0) or ($> == 0))
		{
			$uuid = lc($anvil->System->call({debug => $debug, shell_call => $anvil->data->{path}{exe}{dmidecode}." --string system-uuid"}));
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { uuid => $uuid }});
		}
		else
		{
			# Not running as root, so I have to rely on the cache file, or die if it doesn't 
			# exist.
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 'path::data::host_uuid' => $anvil->data->{path}{data}{host_uuid} }});
			if (not -e $anvil->data->{path}{data}{host_uuid})
			{
				# We're done.
				$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 0, priority => "err", key => "log_0187"});
				return("#!error!#");
			}
			else
			{
				$uuid = $anvil->Storage->read_file({debug => $debug, file => $anvil->data->{path}{data}{host_uuid}});
				$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { uuid => $uuid }});
			}
		}
		
		if ($anvil->Validate->is_uuid({uuid => $uuid}))
		{
			$anvil->data->{HOST}{UUID} = $uuid;
			if (not -e $anvil->data->{path}{data}{host_uuid})
			{
				### TODO: This will need to set the proper SELinux context.
				# Apache run scripts can't call the system UUID, so we'll write it to a text
				# file.
				$anvil->Storage->write_file({
					debug     => $debug, 
					file      => $anvil->data->{path}{data}{host_uuid}, 
					body      => $uuid,
					user      => "apache", 
					group     => "apache",
					mode      => "0666",
					overwrite => 0,
				});
				$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 1, key => "message_0011", variables => { file => $anvil->data->{path}{configs}{'postgresql.conf'} }});
			}
		}
		else
		{
			# Bad UUID.
			$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 0, priority => "err", key => "log_0134", variables => { uuid => $uuid }});
			$anvil->data->{HOST}{UUID} = "";
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "HOST::UUID" => $anvil->data->{HOST}{UUID} }});
		}
	}
	
	# We'll also store the host UUID in a variable.
	if ((not $anvil->data->{sys}{host_uuid}) && ($anvil->data->{HOST}{UUID}))
	{
		$anvil->data->{sys}{host_uuid} = $anvil->data->{HOST}{UUID};
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "sys::host_uuid" => $anvil->data->{sys}{host_uuid} }});
	}
	
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { "HOST::UUID" => $anvil->data->{HOST}{UUID} }});
	return($anvil->data->{HOST}{UUID});
}

=head2 md5sum

This returns the C<< md5sum >> of a given file.

Parameters;

=head3 file

This is the full or relative path to the file. If the file doesn't exist, an empty string is returned.

=cut
sub md5sum
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $sum = "";
	my $file = defined $parameter->{file} ? $parameter->{file} : "";
	
	if (-e $file)
	{
		my $shell_call = $anvil->data->{path}{exe}{md5sum}." ".$file;
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { shell_call => $shell_call }});
		
		my $return = $anvil->System->call({shell_call => $shell_call});
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 'return' => $return }});
		
		# split the sum off.
		$sum = ($return =~ /^(.*?)\s+$file$/)[0];
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { sum => $sum }});
	}
	
	return($sum);
}

=head2 network

This takes an IP address and subnet and returns the network it belongs too. For example;

 my $network = $anvil->Get->network({ip => "10.2.4.1", subnet => "255.255.0.0"});

This would set C<< $network >> to C<< 10.2.0.0 >>.

If the network can't be caluclated for any reason, and empty string will be returned.

Parameters;

=head3 ip (required)

This is the IPv4 IP address being calculated.

=head3 subnet (optional)

This is the subnet of the IP address being calculated.

=cut
sub network
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $network = "";
	my $ip      = defined $parameter->{ip}     ? $parameter->{ip}     : "";
	my $subnet  = defined $parameter->{subnet} ? $parameter->{subnet} : "";
	
	if (not $ip)
	{
		$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 0, priority => "err", key => "log_0020", variables => { method => "Get->network()", parameter => "ip" }});
	}
	if (not $subnet)
	{
		$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 0, priority => "err", key => "log_0020", variables => { method => "Get->network()", parameter => "subnet" }});
	}
	
	my $block = Net::Netmask->new($ip."/".$subnet);
	my $base  = $block->base();
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { base => $base }});
	
	if ($anvil->Validate->is_ipv4({ip => $base}))
	{
		$network = $base;
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { network => $network }});
	}
	
	return($network);
}

 
### TODO: Is this a waste of time / duplicate of System->get_ips()?
=head2 network_details

This method returns the local hostname and IP addresses.

It returns a hash reference containing data in the following keys:

C<< hostname >> = <name>
C<< interface::<interface>::ip >> = <ip_address>
C<< interface::<interface>::netmask >> = <dotted_decimal_subnet>

=cut
sub network_details
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $network      = {};
	my $hostname     = $anvil->System->call({shell_call => $anvil->data->{path}{exe}{hostname}});
	my $ip_addr_list = $anvil->System->call({shell_call => $anvil->data->{path}{exe}{ip}." addr list"});
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 
		hostname     => $hostname, 
		ip_addr_list => $ip_addr_list,
	}});
	$network->{hostname} = $hostname;
	
	my $in_interface = "";
	my $ip_address   = "";
	my $subnet_mask  = "";
	foreach my $line (split/\n/, $ip_addr_list)
	{
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { line => $line }});
		if ($line =~ /^\d+: (.*?):/)
		{
			$in_interface = $1;
			$ip_address   = "";
			$subnet_mask  = "";
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { in_interface => $in_interface }});
			next if $in_interface eq "lo";
			$network->{interface}{$in_interface}{ip}      = "--";
			$network->{interface}{$in_interface}{netmask} = "--";
		}
		if ($in_interface)
		{
			next if $in_interface eq "lo";
			if ($line =~ /inet (.*?)\/(.*?) /)
			{
				$ip_address   = $1;
				$subnet_mask  = $2;
				$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 
					ip_address  => $ip_address,
					subnet_mask => $subnet_mask, 
				}});
				
				if ((($subnet_mask =~ /^\d$/) or ($subnet_mask =~ /^\d\d$/)) && ($subnet_mask < 25))
				{
					$subnet_mask = $anvil->Convert->cidr({cidr => $subnet_mask});
					$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { subnet_mask => $subnet_mask }});
				}
				$network->{interface}{$in_interface}{ip}      = $ip_address;
				$network->{interface}{$in_interface}{netmask} = $subnet_mask;
			}
		}
	}
	
	return($network);
}

=head2 switches

This reads in the command line switches used to invoke the parent program. 

It takes no arguments, and data is stored in 'C<< $anvil->data->{switches}{x} >>', where 'x' is the switch used.

Switches in the form 'C<< -x >>' and 'C<< --x >>' are treated the same and the corresponding 'C<< $anvil->data->{switches}{x} >>' will contain '#!set!#'. 

Switches in the form 'C<< -x foo >>', 'C<< --x foo >>', 'C<< -x=foo >>' and 'C<< --x=foo >>' are treated the same and the corresponding 'C<< $anvil->data->{switches}{x} >>' will contain 'foo'. 

The switches 'C<< -v >>', 'C<< -vv >>', 'C<< -vvv >>' and 'C<< -vvvv >>' will cause the active log level to automatically change to 1, 2, 3 or 4 respectively. Passing 'C<< -V >>' will set the log level to '0'.

Anything after 'C<< -- >>' is treated as a raw string and is not processed. 

=cut
sub switches
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $last_argument = "";
	foreach my $argument (@ARGV)
	{
		if ($last_argument eq "raw")
		{
			# Don't process anything.
			$anvil->data->{switches}{raw} .= " $argument";
		}
		elsif ($argument =~ /^-/)
		{
			# If the argument is just '--', appeand everything after it to 'raw'.
			if ($argument eq "--")
			{
				$last_argument         = "raw";
				$anvil->data->{switches}{raw} = "";
			}
			else
			{
				($last_argument) = ($argument =~ /^-{1,2}(.*)/)[0];
				if ($last_argument =~ /=/)
				{
					# Break up the variable/value.
					($last_argument, my $value) = (split /=/, $last_argument, 2);
					$anvil->data->{switches}{$last_argument} = $value;
				}
				else
				{
					$anvil->data->{switches}{$last_argument} = "#!SET!#";
				}
			}
		}
		else
		{
			if ($last_argument)
			{
				$anvil->data->{switches}{$last_argument} = $argument;
				$last_argument                        = "";
			}
			else
			{
				# Got a value without an argument, so just record it as '#!SET!#'.
				$anvil->data->{switches}{$argument} = "#!SET!#";
			}
		}
	}
	# Clean up the initial space added to 'raw'.
	if ($anvil->data->{switches}{raw})
	{
		$anvil->data->{switches}{raw} =~ s/^ //;
	}
	
	# Adjust the log level if requested.
	$anvil->Log->_adjust_log_level();
	
	return(0);
}

=head2 users_home

This method takes a user's name and returns the user's home directory. If the home directory isn't found, C<< 0 >> is returned.

Parameters;

=head3 user (optional, default is the user name of the real UID (as stored in '$<'))

This is the user whose home directory you are looking for.

=cut
sub users_home
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $home_directory = 0;
	
	my $user = defined $parameter->{user} ? $parameter->{user} : getpwuid($<);
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { user => $user }});
	
	# Make sure the user is only one digit. Sometimes $< (and others) will return multiple IDs.
	if ($user =~ /^\d+ \d$/)
	{
		$user =~ s/^(\d+)\s.*$/$1/;
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { user => $user }});
	}
	
	# If the user is numerical, convert it to a name.
	if ($user =~ /^\d+$/)
	{
		$user = getpwuid($user);
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { user => $user }});
	}
	
	# Still don't have a name? fail...
	if ($user eq "")
	{
		# No user? No bueno...
		$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 0, priority => "err", key => "log_0020", variables => { method => "Get->users_home()", parameter => "user" }});
		return($home_directory);
	}
	
	my $body = $anvil->Storage->read_file({file => $anvil->data->{path}{data}{passwd}});
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { body => $body }});
	foreach my $line (split /\n/, $body)
	{
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { line => $line }});
		if ($line =~ /^$user:/)
		{
			$home_directory = (split/:/, $line)[5];
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { home_directory => $home_directory }});
			last;
		}
	}
	
	# Do I have the a user's $HOME now?
	if (not $home_directory)
	{
		$anvil->Log->entry({source => $THIS_FILE, line => __LINE__, level => 0, priority => "err", key => "log_0061", variables => { user => $user }});
	}
	
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { home_directory => $home_directory }});
	return($home_directory);
}

=head2 uuid

This method returns a new v4 UUID (using 'UUID::Tiny'). It takes no parameters.

=cut
sub uuid
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	my $uuid = create_uuid_as_string(UUID_RANDOM);
	$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { uuid => $uuid }});
	
	return($uuid);
}

# =head3
# 
# Private Functions;
# 
# =cut

#############################################################################################################
# Private functions                                                                                         #
#############################################################################################################

=head2 _salt

This generates a random salt string for use with internal Striker passwords.

=cut
sub _salt
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;

	my $salt        = "";
	my $salt_length = $anvil->data->{sys}{password}{salt_length} =~ /^\d+$/ ? $anvil->data->{sys}{password}{salt_length} : 16;
	my @seed        = (" ", "~", "`", "!", "#", "^", "&", "*", "(", ")", "-", "_", "+", "=", "{", "[", "}", "]", "|", ":", ";", "'", ",", "<", ".", ">", "/");
	my @alpha       = ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z");
	my $seed_count  = @seed;
	my $alpha_count = @alpha;

	my $skip_count = 0;
	for (1..$salt_length)
	{
		# We want to have a little randomness in the salt length, but not skip tooooo many times.
		if ((int(rand(20)) == 2) && ($skip_count <= 3))
		{
			$skip_count++;
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { skip_count => $skip_count }});
			next;
		}
		
		# What character will this string be?
		my $this_integer = int(rand(3));
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { this_integer => $this_integer }});
		if ($this_integer == 0)
		{
			# Inject a random digit
			$salt .= int(rand(10));
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { salt => $salt }});
		}
		elsif ($this_integer == 1)
		{
			# Inject a random letter
			$salt .= $alpha[int(rand($alpha_count))];
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { salt => $salt }});
		}
		else
		{
			# Inject a random character
			$salt .= $seed[int(rand($seed_count))];
			$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { salt => $salt }});
		}
	}

	return($salt);
}


=head2 _wrap_to

This determines how wide the user's terminal currently is and returns that width, as well as store it in C<< sys::terminal::columns >>.

This takes no parameters. If there is a problem reading the column width, C<< 0 >> will be returned.

=cut
sub _wrap_to
{
	my $self      = shift;
	my $parameter = shift;
	my $anvil     = $self->parent;
	my $debug     = defined $parameter->{debug} ? $parameter->{debug} : 3;
	
	# Get the column width
	my $shell_call = $anvil->data->{path}{exe}{tput}." cols";
	my $columns    = $anvil->System->call({
		debug           => $debug, 
		redirect_stderr => 0, 
		shell_call      => $shell_call, 
	});
	if ((not defined $columns) or ($columns !~ /^\d+$/))
	{
		# Set 0.
		$columns = 0;
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { columns => $columns }});
	}
	else
	{
		# Got a good value
		$anvil->data->{sys}{terminal}{columns} = $columns;
		$anvil->Log->variables({source => $THIS_FILE, line => __LINE__, level => $debug, list => { 'sys::terminal::columns' => $anvil->data->{sys}{terminal}{columns} }});
	}

	return($columns);
}

1;
