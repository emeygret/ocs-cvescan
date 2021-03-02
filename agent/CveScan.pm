###############################################################################
## OCSINVENTORY-NG
## Web : http://www.ocsinventory-ng.org
##
## This code is open source and may be copied and modified as long as the source
## code is always made freely available.
## Please refer to the General Public Licence http://www.gnu.org/ or Licence.txt
################################################################################
package Ocsinventory::Agent::Modules::CveScan;
use warnings;
#use strict;
sub new {

    my $name="cvescan"; # Name of the module

    my (undef,$context) = @_;
    my $self = {};

    #Create a special logger for the module
    $self->{logger} = new Ocsinventory::Logger ({
        config => $context->{config}
    });
    $self->{logger}->{header}="[$name]";
    $self->{context}=$context;
    $self->{structure}= {
        name => $name,
        start_handler => $name."_start_handler",    #or undef if don't use this hook
        prolog_writer => undef,    #or undef if don't use this hook
        prolog_reader => undef,    #or undef if don't use this hook
        inventory_handler => $name."_inventory_handler",    #or undef if don't use this hook
        end_handler => undef       #or undef if don't use this hook
    };
    bless $self;
}


######### Hook methods ############
sub cvescan_start_handler {
   my $self = shift;
   my $logger = $self->{logger};
   my $common = $self->{context}->{common};

   $logger->debug("Calling cvescan_start_handler");

   #If we cannot load prerequisite, we disable the module
   unless ($common->can_run("cvescan")){
        $self->{disabled} = 1; # Module is disabled
        $logger->error("cvescan is missing !!");
        $logger->error("Humm my prerequisites are not OK... Disabling module :( :(");
   }
}


sub cvescan_inventory_handler {

    my $self = shift;
    my $logger = $self->{logger};
    my $common = $self->{context}->{common};

    $logger->debug("Yeah you are in cvescan_inventory_handler:)");

    my %cves;
    foreach my $cve (_getCVES()) {
        push @{$common->{xmltags}->{CVESCAN}},
        {
            CVE_ID => [$cve->{CVE_ID}],
            CVE_PRIORITY    => [$cve->{CVE_PRIORITY}],
            CVE_PACKAGE   => [$cve->{CVE_PACKAGE}],
            CVE_FIXED_VERSION  => [$cve->{CVE_FIXED_VERSION}],
            CVE_REPOSITORY  => [$cve->{CVE_REPOSITORY}],
        };
    }

}

1;

sub _getCVES{
     my $cveScanResult = "/tmp/cveScanResult.csv";
     unlink $cveScanResult;
     system("cvescan --csv -p all  > /tmp/cveScanResult.csv 2> /dev/null");
     open(my $fh, '<:encoding(UTF-8)', $cveScanResult ) or die "Could not open file '$cveScanResult' $!";
 
     while(my $line = <$fh>){
         next if $line =~ /^CVE ID/; # skip first line
         chomp $line;
         my ($cve_id, $priority, $package, $fixed_version, $repository) = split(/,/, $line);

         push @cves,
         {
             CVE_ID        => $cve_id,
             CVE_PRIORITY      => $priority,
             CVE_PACKAGE       => $package,
             CVE_FIXED_VERSION => $fixed_version,
             CVE_REPOSITORY    => $repository
         };
     }
     close($fh);
     unlink $cveScanResult; 
     return @cves;

}