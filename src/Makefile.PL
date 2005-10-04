# $Id$

# use 5.008;
use ExtUtils::MakeMaker;

my ($obj, $ldd, $fl) =
    -f '/usr/include/rpmconstant/rpmconstant.h' ?
    ('', '-lrpmconstant', '-DHAVE_RPMCONSTANT') :
    ('rpmconstant.o rpmconstant_internal.o rpmconstanttbl.o', '', '');

sub MY::postamble {
        my $first = <<RPMCONSTTBL;

rpmconstanttbl.c: Makefile rpmh2tbl
	perl rpmh2tbl /usr/include/rpm/*.h > \$@
RPMCONSTTBL
	# This code is to reduce duplication of files
	# in fact it is only usefull for the maintainers of this module
	# if you get the module from CPAN, those files are allready here
	# if you're building from svn, you need rpmconstant directory
	my $second = "";
	if(-d '../../rpmconstant') {
	 $second = <<RPMCONST
rpmconstant.c: ../../rpmconstant/rpmconstant.c
	cp -a \$< \$@

rpmconstant.h: ../../rpmconstant/rpmconstant.h
	cp -a \$< \$@

rpmconstant_internal.c: ../../rpmconstant/rpmconstant_internal.c
	cp -a \$< \$@

rpmh2tbl: ../../rpmconstant/rpmh2tbl
	cp -a \$< \$@
RPMCONST
	}

	$first . $second
}

WriteMakefile(
    NAME         => 'RPM4',
    VERSION_FROM => '../lib/RPM4.pm',
    OBJECT       => "RPM4.o RPM4sign.o $obj",
    INC	         => '-I/usr/include/rpm',
    LIBS         => "-lrpm -lrpmio -lrpmdb -lrpmbuild -lpopt -lz -lbz2 $ldd",
    'CCFLAGS'    => $fl,
);
