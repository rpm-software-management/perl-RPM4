# $Id$

package RPM4::Header::Checks;

use strict;
use warnings;

my @tagstocheck = (
    {
        tag => 'NAME',
        type => 'STRING',
        count => 1,
        mandatory => 1,
    },
    {
        tag => 'VERSION',
        type => 'STRING',
        count => 1,
        mandatory => 1,
    },
    {
        tag => 'RELEASE',
        type => 'STRING',
        count => 1,
        mandatory => 1,
    },
    { tag => 'EPOCH', type => 'INT32', count => 1, },
    {
        tag => 'CHANGELOGTEXT', type => 'STRING_ARRAY',
        countof => [ qw(CHANGELOGNAME CHANGELOGTIME) ],
    },
    { tag => 'CHANGELOGNAME', type => 'STRING_ARRAY', },
    { tag => 'CHANGELOGTIME', type => 'INT32', },
    { tag => 'PACKAGER', type => 'STRING', },
    { tag => 'DISTRIBUTION', type => 'STRING', },
    { tag => 'SUMMARY', type => 'STRING', count => 1, mandatory => 1, },
    { tag => 'DESCRIPTION', type => 'STRING', count => 1, mandatory => 1, },

);

sub reporterror {
    printf(@_);
    print "\n";
}

sub check {
    my ($header) = @_;
    foreach my $check (@tagstocheck) {
        $check->{tag} or next; # buggy check
        
        if (!$header->hastag($check->{tag})) {
            reporterror(
                "tag %s not found",
                $check->{tag},
            ) if($check->{mandatory});
        } elsif (defined($check->{count})) {
            my @t = $header->tag($check->{tag});
            if(scalar(@t) != $check->{count}) {
                reporterror(
                    "Wrong count for tag %s: %d, %d is expected",
                    $check->{tag},
                    scalar(@t),
                    $check->{count},
                );
            }
        }

        if ($check->{countof}) {
            my @t = $header->tag($check->{tag});
            foreach my $co (@{$check->{countof}}) {
                my @t2 = $header->tag($co);
                if (scalar(@t) != scalar(@t2)) {
                    reporterror(
                        "count of tag %s is not the same than %s, %d vs %d",
                        $check->{tag},
                        $co,
                        scalar(@t),
                        scalar(@t2),
                    );
                }
            }
        }
        
        $header->hastag($check->{tag}) or next;
        
        if ($check->{type}) {
            if ($header->tagtype($check->{tag}) != RPM4::tagtypevalue($check->{type})) {
               reporterror(
                   "Wrong tagtype for tag %s: %d, %d is expected",
                   $check->{tag},
                   $header->tagtype($check->{tag}), 
                   RPM4::tagtypevalue($check->{type})
               ); 
           }
        }
    }
}

