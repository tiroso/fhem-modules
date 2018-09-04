package main;
use strict;
use warnings;
use Blocking;
use SNMP;
use JSON;
use Socket;
use Data::Dumper;

my %SNMP_sets = (
    "WriteSingleOID"      => "textField",
);
my %SNMP_gets = (
	"ReadSingleOID"		=> "textField",
	"ReadListOID"		=> "textField",
);

sub SNMP_Initialize($) {
    my ($hash) = @_;

    $hash->{DefFn}      = 'SNMP_Define';
    $hash->{UndefFn}    = 'SNMP_Undef';
    $hash->{SetFn}    	= 'SNMP_Set';
    $hash->{GetFn}    	= 'SNMP_Get';
    $hash->{AttrFn}     = 'SNMP_Attr';

    # Add the search directory.
    &SNMP::addMibDirs("/usr/share/snmp/mibs");

    # Load the modules AND their pre-reqs.
    &SNMP::loadModules('ALL');

    # Wonder-Twin powers, ACTIVATE!
    &SNMP::initMib();

    $hash->{AttrList} =
    "ReadSingleOID:textField "
    ."ReadListOID:textField "
    ."WritePreDefined:textField "
    ."ReadingsValueCorrection:textField "
    ."ReadingsCorrection:textField "
    ."ReadingsToState:textField "
    ."SNMPVersion:1,2,3 "
    ."SNMPCommunity:textField "
    ."SNMPSecName:textField "
    ."SNMPSecLevel:noAuthNoPriv,authNoPriv,authPriv "
    ."SNMPSecEngineId:textField "
    ."SNMPContextEngineId:textField "
    ."SNMPContext:textField "
    ."SNMPAuthProto:MD5,SHA "
    ."SNMPAuthPass:textField "
    ."SNMPPrivProto:DES "
    ."SNMPPrivPass:textField "
    ."SNMPRemotePort:textField "
    ."SNMPUseSprintValue:0,1 "
    ."SNMPUseLongNames:0,1 "
    ."vendor:textField "
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
        $hash->{IP}  = $re;
        readingsSingleUpdate( $hash, "state", "Initialize.", 1 );
        InternalTimer(gettimeofday()+int(1 + rand(30)), "SNMP_AutoUpdate", $hash);
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

sub SNMP_AutoUpdate($){
    my ($hash) = @_;
	my $name = $hash->{NAME};
      
    
    if(scalar devspec2array("TYPE=SNMP:FILTER=RUNNING=1") >= AttrVal("global","SNMPMaxAutoUpdate",1)){
        InternalTimer(gettimeofday()+int(1 + rand(5)), "SNMP_AutoUpdate", $hash);
    }else{
        my $jsoncoder = JSON::XS->new();
        $jsoncoder->allow_nonref();
        $jsoncoder->allow_blessed();
        my %blocking_data = SNMP_DataConstructor($hash);
        
        push(@{$blocking_data{getoidraw}{ReadSingleOIDAuto}},("sysDescr","sysLocation","sysUpTime","sysContact","sysName"));        
        push(@{$blocking_data{getoidraw}{ReadSingleOID}},split(",",AttrVal($name,"ReadSingleOID","")));
        push(@{$blocking_data{getoidraw}{ReadListOID}},split(",",AttrVal($name,"ReadListOID","")));
        
        unless(exists($hash->{Helper}{"GetOid"})){
            $hash->{"RUNNING"}=1;
            $hash->{Helper}{"GetOid"} = BlockingCall("SNMP_GetOid", $name."|".$jsoncoder->encode(\%blocking_data),"SNMP_GetOidFinish", 15, "SNMP_GetOidAborted", $name."|".$jsoncoder->encode(\%blocking_data));            
        }
        InternalTimer(gettimeofday()+int(45 + rand(30)), "SNMP_AutoUpdate", $hash);
    }
}

sub SNMP_Set($@) {
    my ($hash, @param) = @_;
    my $name = shift @param;
    my $opt = shift @param;
    my $value =  join(" ", @param);

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
    
	my $jsoncoder = JSON::XS->new();
	$jsoncoder->allow_nonref();
	$jsoncoder->allow_blessed();
    my %blocking_data = SNMP_DataConstructor($hash);
    
    if($opt =~ /^WriteSingleOID/i){

        push(@{$blocking_data{getoidraw}{WriteSingleOID}},split(",",$value));
	
	for(my $i=0;$i < scalar @{$blocking_data{getoidraw}{WriteSingleOID}};$i++){
		$blocking_data{getoidraw}{WriteSingleOID}[$i] =~ s/^\s+|\s+$//g;
		my $search = $blocking_data{getoidraw}{WriteSingleOID}[$i];
		if(my ($replace) = AttrVal($name,"WritePreDefined","") =~ /(?:^|,)\s*${search}\s*:\s*(.*?)(?:$|,)/){
			$blocking_data{getoidraw}{WriteSingleOID}[$i] =~ s/${search}/${replace}/;
		}
	}
        
        unless(exists($hash->{Helper}{"WriteOid"})){
            $hash->{"RUNNING"}=1;
            $hash->{Helper}{"WriteOid"} = BlockingCall("SNMP_GetOid", $name."|".$jsoncoder->encode(\%blocking_data),"SNMP_GetOidFinish", 15, "SNMP_GetOidAborted", $name."|".$jsoncoder->encode(\%blocking_data));            
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
    my $jsoncoder = JSON::XS->new();
	$jsoncoder->allow_nonref();
	$jsoncoder->allow_blessed();
    my %blocking_data = SNMP_DataConstructor($hash);
	if($opt =~ /^ReadSingleOID$/i){
        
        push(@{$blocking_data{getoidraw}{ReadSingleOID}},split(",",$value)) if($value ne "");
        push(@{$blocking_data{getoidraw}{ReadSingleOID}},split(",",AttrVal($name,"ReadSingleOID",""))) if($value eq "");
        
        unless(exists($hash->{Helper}{"GetOid"})){
            $hash->{"RUNNING"}=1;
            $hash->{Helper}{"GetOid"} = BlockingCall("SNMP_GetOid", $name."|".$jsoncoder->encode(\%blocking_data),"SNMP_GetOidFinish", 15, "SNMP_GetOidAborted", $name."|".$jsoncoder->encode(\%blocking_data));            
        }
    }
    if($opt =~ /^ReadListOID$/i){
                
        push(@{$blocking_data{getoidraw}{ReadListOID}},split(",",$value)) if($value ne "");
        push(@{$blocking_data{getoidraw}{ReadListOID}},split(",",AttrVal($name,"ReadListOID",""))) if($value eq "");
        
        unless(exists($hash->{Helper}{"GetOid"})){
            $hash->{"RUNNING"}=1;
            $hash->{Helper}{"GetOid"} = BlockingCall("SNMP_GetOid", $name."|".$jsoncoder->encode(\%blocking_data),"SNMP_GetOidFinish", 15, "SNMP_GetOidAborted", $name."|".$jsoncoder->encode(\%blocking_data));            
        }
    }
	
	return undef;
}

sub SNMP_GetSingleOid{
    my (%blocking_data) = @_;
    my $hash = $blocking_data{hash};
    my $name = $hash->{NAME};

    my $sess = new SNMP::Session(%{$blocking_data{snmpparam}});    
    
    my @getoidraw = (@{$blocking_data{getoidraw}{ReadSingleOID}},@{$blocking_data{getoidraw}{ReadSingleOIDAuto}});
    
    for (my $o=0;$o < scalar @getoidraw;$o++){
        my $getoidrawstring = $getoidraw[$o];
        $getoidrawstring =~ s/^\s+|\s+$//g;
        
        if(my ($oid) = $getoidrawstring =~ /^(.+?)\s*(?:\(|$)/){
        
            my ($instance) = $getoidrawstring =~ /(?:\(|\|)\s*i\s*\=\s*(\d+)/;
            $instance = "0" if(!defined($instance));
            
            
            my $vb = new SNMP::Varbind([$oid,$instance]); # '0' is the instance.
	    if(defined($sess)){
		my $var = $sess->get($vb); # Get exactly what we asked for.
			if ($sess->{ErrorNum}) {
				my $rc = AttrVal($name,"ReadingsCorrection","");
				my $tag = $oid;
				my ($userreading) = $rc =~ /(?:^|,)\s*${tag}\s*=\s*(.+?)\s*(?:,|$)/i;
				$userreading = $oid if(!defined($userreading) || $userreading ne $oid);
				$blocking_data{getoid}{$userreading."000"}{type}=1;
				$blocking_data{getoid}{$userreading."000"}{error}=1;
				$blocking_data{getoid}{$userreading."000"}{var}="Error: " . $sess->{ErrorStr};
			}else{

				my $rc = AttrVal($name,"ReadingsCorrection","");
				my $tag = $vb->tag;
				my ($userreading) = $rc =~ /(?:^|,)\s*${tag}\s*=\s*(.+?)\s*(?:,|$)/i;
				$userreading = $vb->tag if(!defined($userreading) || $userreading ne $vb->tag);

				my $reading = $var;
				my $rvc = AttrVal($name,"ReadingsValueCorrection","");

				while (my ($search, $replace) = $rvc =~ /(?:^|,)\s*${userreading}\s*\(\s*(.+?)\s*=\s*(.+?)\s*(?:\)|\||,|$)/) {
					$reading =~ s/^${search}$/${replace}/;
					$rvc =~ s/\s*${search}\s*=\s*${replace}\s*//;
				}

				$reading =~ s/^\"|\"$//g;
				my $iidform = 0;
				$iidform = sprintf("%03d", $vb->iid)if ( $vb->iid =~ /^[0-9]+$/ );
				$blocking_data{getoid}{$userreading . "." . $iidform}{error}=0;
				$blocking_data{getoid}{$userreading . "." . $iidform}{iid}=$vb->iid;
				$blocking_data{getoid}{$userreading . "." . $iidform}{var}=$reading if($reading ne "");
				$blocking_data{getoid}{$userreading . "." . $iidform}{var}="(none)" if($reading eq "");
			}
	    }
        }
    }
    return %blocking_data;
}

sub SNMP_GetListOid{
    my (%blocking_data) = @_;
    my $hash = $blocking_data{hash};
    my $name = $hash->{NAME};

    my $sess = new SNMP::Session(%{$blocking_data{snmpparam}});    
    
    my @getoidraw = (@{$blocking_data{getoidraw}{ReadListOID}},@{$blocking_data{getoidraw}{ReadListOIDAuto}});
    
    for (my $o=0;$o < scalar @getoidraw;$o++){
        my $getoidrawstring = $getoidraw[$o];
        $getoidrawstring =~ s/^\s+|\s+$//g;
        
        if(my ($oid) = $getoidrawstring =~ /^(.+?)(?:,|$)/){
            
            
            my $vb = new SNMP::Varbind([$oid]); # '0' is the instance.
            
            
            for (my $var = $sess->getnext($vb);($vb->tag eq $oid) and not ($sess->{ErrorNum}); $var = $sess->getnext($vb)) {
            	my $userreading;
                my $rc = AttrVal($name,"ReadingsCorrection","");
                my $tag = $vb->tag;
                my ($userreading) = $rc =~ /(?:^|,)\s*${tag}\s*=\s*(.+?)\s*(?:,|$)/i;
                $userreading = $vb->tag if(!defined($userreading) && $userreading ne $vb->tag);
                
                my $reading = $var;
                my $rvc = AttrVal($name,"ReadingsValueCorrection","");
                
                while (my ($search, $replace) = $rvc =~ /(?:^|,)\s*${userreading}\s*\(\s*(.+?)\s*=\s*(.+?)\s*(?:\)|\||,|$)/) {
                    $reading =~ s/^${search}$/${replace}/;
                    $rvc =~ s/\s*${search}\s*=\s*${replace}\s*//;
                }
                $reading =~ s/^\"|\"$//g;
		my $iidform = sprintf("%03d", $vb->iid);
                $blocking_data{getoid}{$userreading . "." . $iidform}{error}=0;
                $blocking_data{getoid}{$userreading . "." . $iidform}{iid}=$vb->iid;
                $blocking_data{getoid}{$userreading . "." . $iidform}{var}=$reading if($reading ne "");
                $blocking_data{getoid}{$userreading . "." . $iidform}{var}="(none)" if($reading eq "");
            }
            if ($sess->{ErrorNum}) {
                my $rc = AttrVal($name,"ReadingsCorrection","");
                my $tag = $oid;
                my ($userreading) = $rc =~ /(?:^|,)\s*${tag}\s*=\s*(.+?)\s*(?:,|$)/i;
                $userreading = $oid if(!defined($userreading) && $userreading ne $oid);
                $blocking_data{getoid}{$userreading."000"}{error}=1;
                $blocking_data{getoid}{$userreading."000"}{var}="Error: " . $sess->{ErrorStr};
            }
            
        }
    }
    return %blocking_data;
}

sub SNMP_WriteSingleOID{
    my (%blocking_data) = @_;
    my $hash = $blocking_data{hash};
    my $name = $hash->{NAME};

    my $sess = new SNMP::Session(%{$blocking_data{snmpparam}});    
    
    my @getoidraw = (@{$blocking_data{getoidraw}{WriteSingleOID}});
    
    for (my $o=0;$o < scalar @getoidraw;$o++){
        my $getoidrawstring = $getoidraw[$o];
        $getoidrawstring =~ s/^\s+|\s+$//g;
        
        if(my ($oid,$oidvalue) = $getoidrawstring =~ /^(.+?)\s*=\s*(.+?)\s*(?:\(|$)/){
	my ($instance) = $getoidrawstring =~ /(?:\(|\|)\s*i\s*\=\s*(\d+)/;
            $instance = "0" if(!defined($instance));
            my $vb = new SNMP::Varbind([$oid,$instance,$oidvalue ]);

		# This does it!
		$sess->set($vb);
		if ( $sess->{ErrorNum} ) {
		  Log3 $hash->{NAME}, 5, $hash->{NAME} . ": Got " . $sess->{ErrorStr};
		}
            
            
            
        }
    }
    return %blocking_data;
}

sub SNMP_DataConstructor{
    my ($hash) = @_;
    my $name = $hash->{NAME};
    
    my %blocking_data = (
            "hash"  => $hash,
            "getoidraw"	=>	{
                "ReadSingleOID"=>[],
                "ReadSingleOIDAuto"=>[],
                "ReadListOID"=>[],
                "ReadListOIDAuto"=>[],
		"WriteSingleOID"=>[]
            },
            "getoid" => {},
            "snmpparam" => {
                "DestHost" => InternalVal($name,"IP","127.0.0.1"),
                "UseSprintValue" => AttrVal($name,"SNMPUseSprintValue","1"),
                "UseLongNames" => AttrVal($name,"SNMPUseLongNames","0"),
            }
        );
   	$blocking_data{snmpparam}{"Version"} = AttrVal($name,"SNMPVersion","") if (AttrVal($name,"SNMPVersion","") ne "");
	$blocking_data{snmpparam}{"Community"} = AttrVal($name,"SNMPCommunity","") if (AttrVal($name,"SNMPCommunity","") ne "");
	$blocking_data{snmpparam}{"SecName"} = AttrVal($name,"SNMPSecName","") if (AttrVal($name,"SNMPSecName","") ne "");
	$blocking_data{snmpparam}{"SecLevel"} = AttrVal($name,"SNMPSecLevel","") if (AttrVal($name,"SNMPSecLevel","") ne "");
	$blocking_data{snmpparam}{"SecEngineId"} = AttrVal($name,"SNMPSecEngineId","") if (AttrVal($name,"SNMPSecEngineId","") ne "");
	$blocking_data{snmpparam}{"ContextEngineId"} = AttrVal($name,"SNMPContextEngineId","") if (AttrVal($name,"SNMPContextEngineId","") ne "");
	$blocking_data{snmpparam}{"Context"} = AttrVal($name,"SNMPContext","") if (AttrVal($name,"SNMPContext","") ne "");
	$blocking_data{snmpparam}{"AuthProto"} = AttrVal($name,"SNMPAuthProto","") if (AttrVal($name,"SNMPAuthProto","") ne "");
	$blocking_data{snmpparam}{"AuthPass"} = AttrVal($name,"SNMPAuthPass","") if (AttrVal($name,"SNMPAuthPass","") ne "");
	$blocking_data{snmpparam}{"PrivProto"} = AttrVal($name,"SNMPPrivProto","") if (AttrVal($name,"SNMPPrivProto","") ne "");
	$blocking_data{snmpparam}{"PrivPass"} = AttrVal($name,"SNMPPrivPass","") if (AttrVal($name,"SNMPPrivPass","") ne "");
	$blocking_data{snmpparam}{"RemotePort"} = AttrVal($name,"SNMPRemotePort","") if (AttrVal($name,"SNMPRemotePort","") ne "");
    	Log3 $hash->{NAME}, 5, $hash->{NAME} . ": " . Dumper(%blocking_data);
    return %blocking_data;
}

sub SNMP_GetOid($) {
    my ($string) = @_;
    my ($hashname, $blocking_recv_data) = split("\\|", $string);
	my $jsoncoder = JSON::XS->new();
        $jsoncoder->allow_nonref();
        $jsoncoder->allow_blessed();
	my %blocking_data = %{$jsoncoder->decode($blocking_recv_data)};
    my $hash = $blocking_data{hash};
            Log3 $hash->{NAME}, 3, $hash->{NAME} . ": Funktionauslesen wird gestartet";
    
    %blocking_data = SNMP_WriteSingleOID(%blocking_data);
    %blocking_data = SNMP_GetSingleOid(%blocking_data);
    %blocking_data = SNMP_GetListOid(%blocking_data);
    

	return $hashname ."|".$jsoncoder->encode(\%blocking_data);
}

sub SNMP_GetOidFinish($) {
	my ($string) = @_;
    my ($name, $blocking_recv_data) = split("\\|", $string);
	my $jsoncoder = JSON::XS->new();
        $jsoncoder->allow_nonref();
        $jsoncoder->allow_blessed();
	my %blocking_data = %{$jsoncoder->decode($blocking_recv_data)};
    my $hash = $defs{$name};
    $hash->{"RUNNING"}=0;
    
    my $errorcount = 0;
    foreach my $k (keys %{$blocking_data{getoid}}){
        readingsSingleUpdate( $hash, "r.".$k, $blocking_data{getoid}{$k}{var}, 1 );
        $errorcount++ if ($blocking_data{getoid}{$k}{error});
    }
    readingsSingleUpdate( $hash, "DataRefresh", gettimeofday(), 1 );
    readingsSingleUpdate( $hash, "DataRefreshErrors", $errorcount, 1 );
    
    
    
    
    my $tempstate = AttrVal($name,"ReadingsToState","Name: %r.sysName.000% / Location: %r.sysLocation.000% / Contact: %r.sysContact.000%");
    while (my ($searchattr) = $tempstate =~ /\%(.*?)\%/) {
        my $searchattrvalue = ReadingsVal($name,$searchattr,"");
        $tempstate =~ s/\%${searchattr}\%/${searchattrvalue}/;
    }
    
    readingsSingleUpdate( $hash, "state", $tempstate, 1 );        
    
	delete($hash->{Helper}{"GetOid"});
		delete($hash->{Helper}{"WriteOid"});

	return;
}

sub SNMP_GetOidAborted($) {
   my ($string) = @_;
    my ($hashname, $blocking_recv_data) = split("\\|", $string);
	my $jsoncoder = JSON::XS->new();
        $jsoncoder->allow_nonref();
        $jsoncoder->allow_blessed();
	my %blocking_data = %{$jsoncoder->decode($blocking_recv_data)};
    my $hash = $defs{$hashname};
    $hash->{"RUNNING"}=0;
    
	delete($hash->{Helper}{"GetOid"});
	delete($hash->{Helper}{"WriteOid"});
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
