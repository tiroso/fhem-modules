package main;
use strict;
use warnings;
use Blocking;
use JSON;

my %SNMP_sets = (
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
    ."SNMPMibs:textField "
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
		SNMP_savePassword($hash, $value);		
	}
	if($opt =~ /^power$/i){
		if($value =~ /^(on|off)$/i){
			SNMP_Command("$name|send|power_$1");
			$hash->{Helper}{Running_Pid_send} = BlockingCall("SNMP_Command", $name."|send|power_$1","SNMP_CommandFinish", 30, "SNMP_CommandAborted", $name."|send") unless(exists($hash->{Helper}{Running_Pid_send}));
		}
	}
	if($opt =~ /^input$/i){
		if($value =~ /^(digital|network|storage|video|rgb).(\d+)$/i){
			$hash->{Helper}{Running_Pid_send} = BlockingCall("SNMP_Command", $name."|send|input_$1_$2","SNMP_CommandFinish", 30, "SNMP_CommandAborted", $name."|send") unless(exists($hash->{Helper}{Running_Pid_send}));
		}
	}
	if($opt =~ /^mute$/i){
		if($value =~ /^(audio|video|both).(on|off)$/i){
			$hash->{Helper}{Running_Pid_send} = BlockingCall("SNMP_Command", $name."|send|mute_$1_$2","SNMP_CommandFinish", 30, "SNMP_CommandAborted", $name."|send") unless(exists($hash->{Helper}{Running_Pid_send}));
		}
	}

	
	return undef;
}

sub SNMP_Get($@) {
	my ($hash, @param) = @_;
	my $name = shift @param;
	my $opt = shift @param;
	my $value = join(" ", @param);
	
	if (!exists($SNMP_gets{$opt}))  {
		my @cList;
		foreach my $k (keys %SNMP_gets) {
			my $opts = undef;
			$opts = $SNMP_gets{$k};

			if (defined($opts)) {
				push(@cList,$k . ':' . $opts);
			} else {
				push (@cList,$k);
			}
		} # end foreach

		return "SNMP_Get: Unknown argument $opt, choose one of " . join(" ", @cList);	
    } # error unknown opt handling
	if($opt =~ /^oitd$/i){
        my $attrmib = AttrVal($name, "SNMPReadOITDs", "")
        while ($attrmib =~ /(?:^|,)((?:\.\d+){1,}):([a-z0-9]+)/gi) {
            my $oid = $1;
            my $oidname = $2;
            my $tempoid = $oid;
            $tempoid =~ tr/0-9//dc;
            $hash->{Helper}{"GetOid_".$tempoid} = BlockingCall("SNMP_GetOid", $name."|".$oid."|".$oidname,"SNMP_GetOidFinish", 30, "SNMP_GetOidAborted", $name."|".$oid."|".$oidname."|1|Aborted") unless(exists($hash->{Helper}{"GetOid_".$tempoid}));
        } 
            
    }
	
	return undef;
}

sub SNMP_GetOid($) {
    my ($string) = @_;
	my ($hashname, $oid, $oidname) = split("\\|", $string);
	my $hash = $defs{$hashname};

	return "$hashname|$oid|$oidname|error|result";
}

sub SNMP_GetOidFinish($) {
    my ($string) = @_;
	my ($hashname, $oid, $oidname, $error, $result) = split("\\|", $string);
	my $hash = $defs{$hashname};
	my $tempoid = $oid;
    $tempoid =~ tr/0-9//dc;
    
	delete($hash->{Helper}{"GetOid_".$tempoid});
	return;
}

sub SNMP_GetOidAborted($) {
    my ($string) = @_;
	my ($hashname, $oid, $oidname, $error, $result) = split("\\|", $string);
	my $hash = $defs{$hashname};
	my $tempoid = $oid;
    $tempoid =~ tr/0-9//dc;
    
	delete($hash->{Helper}{"GetOid_".$tempoid});
}

sub SNMP_Attr(@) {
	my ( $cmd, $name, $attrName, $attrValue ) = @_;
	my $hash = $defs{$name};
	if ($cmd eq "set") {
		if ($attrName eq "SNMPPort") {
			if ($attrValue !~ /\d+/) {
				return "Bitte gib einen Port an (Zahl)";
			}
		}
		if ($attrName eq "SNMPInterval") {
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

<a name="SNMP"></a>
<h3>SNMP</h3>


=end html

=cut
