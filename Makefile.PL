# $Id$

# use 5.008;
use ExtUtils::MakeMaker;
use Getopt::Long;

#- require at least rpm 4.2
my $rpm_version = `rpm --version`;
$rpm_version =~ s/RPM version //;
$rpm_version =~ /^(?:[5-9]|\d{2}|4\.[2-9])/
    or die <<BARF;
Unable to build Hdlist with too old (or undetected) rpm version $rpm_version
BARF

sub MY::postamble {
    <<MAKECHANGELOG;
.PHONY: ChangeLog

ChangeLog:
	LC_ALL=C svn update && LC_ALL=C svn log --verbose > \$@

rpm: dist
	rpm --rmsource --define "_sourcedir `pwd`" -ba perl-Hdlist.spec
MAKECHANGELOG
}

WriteMakefile(
    NAME	 => 'RPM4',
    VERSION_FROM => 'lib/RPM4.pm',
    DIR          => [ 'src' ],
    'EXE_FILES'  => [ qw(bin/rpm_produced bin/rpmresign bin/hrpmreb) ],
);
