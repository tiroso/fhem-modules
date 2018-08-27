package main;
use strict;
use warnings;
use Blocking;
use JSON;

my %SNMP_sets = (
    "update"    => "noArg",
    "send"      => "textField",
);
my %SNMP_gets = (
	"oitd"		=> "textField",
);

sub SNMP_Initialize($) {
    my ($hash) = @_;

    $hash->{DefFn}      = 'SNMP_Define';
    $hash->{UndefFn}    = 'SNMP_Undef';
    $hash->{SetFn}    	= 'SNMP_Set';
    $hash->{GetFn}    	= 'SNMP_Get';
    $hash->{AttrFn}     = 'SNMP_Attr';


    $hash->{AttrList} =
    "SNMPReadOITDs:textField "
    ."SNMPMibs":textField "
    . $readingFnAttributes;
        
}

sub SNMP_Define($$) {
    my ($hash, $def) = @_;
    my @param = split('[ \t]+', $def);

    $hash->{name}  = $param[0];
    if(int(@param) < 3) {
        return "zu wenig Parameter: define <name> SNMP <IP Adresse>";
    }
    splice(@param,0,2);
    my $re = join(" ",@param);
    if($re =~ /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/){
        $hash->{DEF}  = $re;
        return undef;
    }else{
        return "Parameterfeheler: Parameter muss eine IP sein <A.B.C.D>";
    }
}


sub SNMP_Undef($$) {
    my ($hash, $arg) = @_; 
    RemoveInternalTimer($hash);
    return undef;
}



sub SNMP_Set($@) {
    my ($hash, @param) = @_;
    my $name = lc shift @param;
    my $opt = lc shift @param;
    my $value =  lc join(" ", @param);

    if (!exists($SNMP_sets{$opt}))  {
        my @cList;
        foreach my $k (keys %SNMP_sets) {
            my $opts = undef;
            $opts = $SNMP_sets{$k};

            if (defined($opts)) {
                push(@cList,$k . ':' . $opts);
            } else {
                push (@cList,$k);
            }
        } # end foreach

        return "SNMP_Set: Unknown argument $opt, choose one of " . join(" ", @cList);	
    } # error unknown opt handling
    
	if($opt =~ /^auth$/i){
		PJLINK_savePassword($hash, $value);		
	}
	if($opt =~ /^power$/i){
		if($value =~ /^(on|off)$/i){
			PJLINK_Command("$name|send|power_$1");
			$hash->{Helper}{Running_Pid_send} = BlockingCall("PJLINK_Command", $name."|send|power_$1","PJLINK_CommandFinish", 30, "PJLINK_CommandAborted", $name."|send") unless(exists($hash->{Helper}{Running_Pid_send}));
		}
	}
	if($opt =~ /^input$/i){
		if($value =~ /^(digital|network|storage|video|rgb).(\d+)$/i){
			$hash->{Helper}{Running_Pid_send} = BlockingCall("PJLINK_Command", $name."|send|input_$1_$2","PJLINK_CommandFinish", 30, "PJLINK_CommandAborted", $name."|send") unless(exists($hash->{Helper}{Running_Pid_send}));
		}
	}
	if($opt =~ /^mute$/i){
		if($value =~ /^(audio|video|both).(on|off)$/i){
			$hash->{Helper}{Running_Pid_send} = BlockingCall("PJLINK_Command", $name."|send|mute_$1_$2","PJLINK_CommandFinish", 30, "PJLINK_CommandAborted", $name."|send") unless(exists($hash->{Helper}{Running_Pid_send}));
		}
	}

	
	return undef;
}

sub PJLINK_Command($) {
    my ($string) = @_;
	my ($hashname, $opt, $type) = split("\\|", $string);
	my $hash = $defs{$hashname};
	my $encoder = JSON::XS->new();
	$encoder->allow_nonref();
	
	my $command;

	my %return = (
					"err"	=>	8,
					"err_txt"	=>	[	"OK",						# 0
										"ERR_COMMAND (ERR1)",		# 1	
										"ERR_PARAMETER (ERR2)",		# 2
										"ERR_UNAVL_TIME (ERR3)",	# 3
										"ERR_PRJT_FAIL (ERR4)",		# 4
										"ERR_NETWORK",				# 5
										"ERR_AUTH",					# 6
										"WARNING",					# 7
										"ERROR",					# 8
										"ERR_TIMEOUT",				# 9
										"ERR_FHEM_TIMEOUT",			# 10
										"ERR_PARSE"					# 11
									]
				 );
				 
	my $socket = IO::Socket::INET->new(
		PeerAddr => InternalVal($hashname, "DEF", "127.0.0.1"),
		PeerPort => AttrVal($hashname, "PJLINKPort", "4352"),
		Proto    => 'tcp',
		Timeout  => AttrVal($hashname, "PJLINKPort", "10"),
	);
	unless($socket && $socket->connected){
		$return{"err"}=5;
		return "$hashname|$opt|" . $encoder->encode(\%return);
	}
	$socket->autoflush(1);
	
	my $resp;
	$socket->recv($resp, 128);
	Log(3,$resp);
	# false, unless format is correct
	unless (defined $resp && $resp =~ /^PJLINK ([01])( ([0-9a-fA-F]+))?\x0d$/){
		$return{"err"}=5;
		return "$hashname|$opt|" . $encoder->encode(\%return);
	}
	# true, no auth required
	if ($1 == 1){
		unless ($3){
			$return{"err"}=11;
			return "$hashname|$opt|" . $encoder->encode(\%return);
		}
		my $digest = Digest::MD5::md5_hex($3 . PJLINK_readPassword($hash));
		$socket->send($digest . "%1POWR ?\xd");
		$socket->recv($resp, 32);
		unless(defined $resp && $resp =~ /^%1POWR=\d\x0d$/){
			$return{"err"}=6;
			return "$hashname|$opt|" . $encoder->encode(\%return);
		}
	}
	
	if($opt eq "send"){
		if($type =~ /^power_(on|off)$/){
			if($1 eq "on"){
				$command ="%1POWR 1\xd";
			}else{
				$command ="%1POWR 0\xd";
			}
		}
		# MUTE_VIDEO	=> 1,
		# MUTE_AUDIO	=> 2,
		# MUTE_BOTH		=> 3,
		if($type =~ /^mute_(audio|video|both)_(on|off)$/){
			if($1 eq "video"){
				if($2 eq "on"){
					$command ="%AVMT 11\xd";
				}else{
					$command ="%AVMT 10\xd";
				}
			}elsif($1 eq "audio"){
				if($2 eq "on"){
					$command ="%AVMT 21\xd";
				}else{
					$command ="%AVMT 20\xd";
				}
			}
			elsif($1 eq "both"){
				if($2 eq "on"){
					$command ="%AVMT 31\xd";
				}else{
					$command ="%AVMT 30\xd";
				}
			}
		}
		# INPUT_RGB	=> 1,
		# INPUT_VIDEO	=> 2,
		# INPUT_DIGITAL	=> 3,
		# INPUT_STORAGE	=> 4,
		# INPUT_NETWORK	=> 5,
		if($type =~ /^input_(digital|network|storage|video|rgb)_(\d+)$/i){
			if($1 eq "rgb"){
				$command ="%1INPT 1$2\xd";
			}elsif($1 eq "video"){
				$command ="%1INPT 2$2\xd";
			}elsif($1 eq "digital"){
				$command ="%1INPT 3$2\xd";
			}elsif($1 eq "storage"){
				$command ="%1INPT 4$2\xd";
			}elsif($1 eq "network"){
				$command ="%1INPT 5$2\xd";
			}
		}
	}
	$resp = undef;
	$socket->send($command);
	$socket->recv($resp, 32);
	
	if (defined $resp && $resp =~ /^%1.*=(.*)\x0d$/ && $opt eq "send") {
		if ($1 =~ /ok/i) {
			$return{"err"}=0;
			return "$hashname|$opt|" . $encoder->encode(\%return);
		}elsif($1 =~ /err(\d)/i) {
			$return{"err"}=$1;
			return "$hashname|$opt|" . $encoder->encode(\%return);
		}
	} else {
		$return{"err"}=5;
		return "$hashname|$opt|" . $encoder->encode(\%return);
	}
	
	$socket->close;
	return "$hashname|$opt|" . $encoder->encode(\%return);
}

sub PJLINK_CommandFinish($) {
    my ($string) = @_;
	my ($hashname, $opt, $result) = split("\\|", $string);
	my $hash = $defs{$hashname};
	
	my $decoder = JSON::XS->new();
	$decoder->allow_nonref();
	my %return = %{$decoder->decode($result)};

	if($return{"err"}>0){
		readingsSingleUpdate( $hash, "${opt}_result", $return{"err"}, 1 );
		readingsSingleUpdate( $hash, "${opt}_result_text", $return{"err_txt"}[$return{"err"}], 1 );
	}
	delete($hash->{Helper}{"Running_Pid_${opt}"});
	return;
}

sub PJLINK_CommandAborted($) {
    my ($string) = @_;
	my ($hashname,$opt) = split("\\|", $string);
	my $hash = $defs{$hashname};
	readingsSingleUpdate( $hash, "${opt}_result", "10", 1 );
	readingsSingleUpdate( $hash, "${opt}_result_text", "ERR_FHEM_TIMEOUT", 1 );
	delete($hash->{Helper}{"Running_Pid_${opt}"});
	return;
}

sub PJLINK_Get($@) {
	my ($hash, @param) = @_;
	my $name = shift @param;
	my $opt = shift @param;
	my $value = join(" ", @param);
	
	if (!exists($gets{$opt}))  {
		my @cList;
		foreach my $k (keys %gets) {
			my $opts = undef;
			$opts = $gets{$k};

			if (defined($opts)) {
				push(@cList,$k . ':' . $opts);
			} else {
				push (@cList,$k);
			}
		} # end foreach

		return "PJLINK_Get: Unknown argument $opt, choose one of " . join(" ", @cList);	} # error unknown opt handling
	if($opt =~ /^information$/i){
		$hash->{Helper}{Running_Pid_get} = BlockingCall("PJLINK_Command", $name."|get|all","PJLINK_CommandFinish", 30, "PJLINK_CommandAborted", $name."|get") unless(exists($hash->{Helper}{Running_Pid_get}));
	}
	
	return undef;
}

#####################################
# Speichert das Passwort
sub PJLINK_savePassword($$)
{
    my ($hash, $password) = @_;
     
    my $index = $hash->{TYPE}."_".$hash->{NAME}."_password";
    my $key = getUniqueId().$index;
    
    my $enc_password = "";
    
    if(eval "use Digest::MD5;1")
    {
        $key = Digest::MD5::md5_hex(unpack "H*", $key);
        $key .= Digest::MD5::md5_hex($key);
    }
    
    for my $char (split //, $password)
    {
        my $encode=chop($key);
        $enc_password.=sprintf("%.2x",ord($char)^ord($encode));
        $key=$encode.$key;
    }
    
    my $err = setKeyValue($index, $enc_password);
    return "Fehler beim abspeichern des Passwortes - $err" if(defined($err));
    
    return "Passwort erfolgreich gespeichert";
} # Ende PJLINK_savepassword

#####################################
# Speichert den Benutzer
sub PJLINK_saveUser($$)
{
    my ($hash, $user) = @_;
     
    my $index = $hash->{TYPE}."_".$hash->{NAME}."_user";
    my $key = getUniqueId().$index;
    
    my $enc_user = "";
    
    if(eval "use Digest::MD5;1")
    {
        $key = Digest::MD5::md5_hex(unpack "H*", $key);
        $key .= Digest::MD5::md5_hex($key);
    }
    
    for my $char (split //, $user)
    {
        my $encode=chop($key);
        $enc_user.=sprintf("%.2x",ord($char)^ord($encode));
        $key=$encode.$key;
    }
    
    my $err = setKeyValue($index, $enc_user);
    return "Fehler beim abspeichern des Benutzers - $err" if(defined($err));
    
    return "Benutzer erfolgreich gespeichert";
} # Ende PJLINK_speicherbenutzer

#####################################
# liest das PJLINK Passwort
sub PJLINK_readPassword($)
{
   my ($hash) = @_;
   my $name = $hash->{NAME};

   my $index = $hash->{TYPE}."_".$hash->{NAME}."_password";
   my $key = getUniqueId().$index;

   my ($password, $err);

   ($err, $password) = getKeyValue($index);

   if ( defined($err) ) {
      return undef;
   }  
    
   if ( defined($password) ) {
      if ( eval "use Digest::MD5;1" ) {
         $key = Digest::MD5::md5_hex(unpack "H*", $key);
         $key .= Digest::MD5::md5_hex($key);
      }

      my $dec_password = '';
     
      for my $char (map { pack('C', hex($_)) } ($password =~ /(..)/g)) {
         my $decode=chop($key);
         $dec_password.=chr(ord($char)^ord($decode));
         $key=$decode.$key;
      }
     
      return $dec_password;
   }
   else {
      return undef;
   }
} # end PJLINK_readPassword

#####################################
# liest den PJLINK Benutzer
sub PJLINK_readUser($)
{
   my ($hash) = @_;
   my $name = $hash->{NAME};

   my $index = $hash->{TYPE}."_".$hash->{NAME}."_user";
   my $key = getUniqueId().$index;

   my ($user, $err);

   ($err, $user) = getKeyValue($index);

   if ( defined($err) ) {
      return undef;
   }  
    
   if ( defined($user) ) {
      if ( eval "use Digest::MD5;1" ) {
         $key = Digest::MD5::md5_hex(unpack "H*", $key);
         $key .= Digest::MD5::md5_hex($key);
      }

      my $dec_user = '';
     
      for my $char (map { pack('C', hex($_)) } ($user =~ /(..)/g)) {
         my $decode=chop($key);
         $dec_user.=chr(ord($char)^ord($decode));
         $key=$decode.$key;
      }
     
      return $dec_user;
   }
   else {
      return undef;
   }
} # end PJLINK_readUser

sub PJLINK_Attr(@) {
	my ( $cmd, $name, $attrName, $attrValue ) = @_;
	my $hash = $defs{$name};
	if ($cmd eq "set") {
		if ($attrName eq "PJLINKPort") {
			if ($attrValue !~ /\d+/) {
				return "Bitte gib einen Port an (Zahl)";
			}
		}
		if ($attrName eq "PJLINKInterval") {
			if ($attrValue !~ /\d+/) {
				return "Bitte gib ein Interval an (Zahl)";
			}
		}
	}
	return undef;

}


1;

=pod
=begin html

<a name="PJLINK"></a>
<h3>PJLINK</h3>


=end html

=cut
