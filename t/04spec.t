# $Id$

use strict;
use Test::More tests => 24;
use FindBin qw($Bin);
use File::Temp qw(tempdir);
use RPM4;

my %info = RPM4::moduleinfo();

my $testdir = tempdir( CLEANUP => 1 );
mkdir("$testdir/$_") foreach (qw(BUILD RPMS RPMS/noarch SRPMS));

my $passphrase = "RPM4";

RPM4::add_macro("_tmppath $testdir");
RPM4::add_macro("_builddir $testdir");
RPM4::add_macro("_topdir $testdir");
RPM4::add_macro("_signature gpg");
RPM4::add_macro("_gpg_name RPM4 test key");
RPM4::add_macro("_gpg_path $Bin/gnupg");

ok((RPM4::installsrpm("$Bin/test-rpm-1.0-1mdk.src.rpm"))[0] =~ m/test-rpm\.spec$/, "installsrpms works");
ok(!RPM4::installsrpm("$Bin/test-rpm-1.0-1mdk.noarch.rpm"), "installsrpms works");

my $spec;
if ($info{Hack} eq "Yes") {
    ok( defined(RPM4::Spec->new()), "Create an empty spec object");
} else {
    ok(! defined(RPM4::Spec->new()), "Create an empty spec object don't works");
}
ok(!defined($spec = RPM4::Spec->new("$Bin/test-rpm-1.0-1mdk.noarch.rpm")), "Loading a bad spec file");
ok($spec = RPM4::Spec->new("$Bin/test-rpm.spec", passphrase => $passphrase), "Loading a spec file");

my @rpms = $spec->binrpm;
ok(@rpms == 1, "Can find binary package");
ok($rpms[0] =~ m!noarch/test-rpm-1.0-1mdk.noarch.rpm$!, "binrpm return good value");

ok($spec->srcrpm =~ m!SRPMS/test-rpm-1.0-1mdk.src.rpm$!, "srcrpm return good value");

ok(!defined($spec->check()), "Running spec::check");

my $h;
ok(defined($h = $spec->srcheader()), "Geting source header before build");
ok($h->queryformat("%{NAME}") eq "test-rpm", "can querying header give by spec");

ok($spec->build([ qw(PREP) ]) == 0, "simulate rpm -bp (check prep)");
ok($spec->build([ qw(BUILD) ]) == 0, "simulate rpm -bc");
ok($spec->build([ qw(INSTALL CHECK) ]) == 0, "simulate rpm -bi");
ok($spec->build([ qw(FILECHECK) ]) == 0, "simulate rpm -bl");
ok($spec->build([ qw(PACKAGEBINARY CLEAN) ]) == 0, "simulate rpm -bb (binary, clean)");
ok($spec->build([ qw(PACKAGESOURCE) ]) == 0, "simulate rpm -bs");
ok($spec->rpmbuild("bb") == 0, "testing spec->rpmbuild(-bb)");
ok($spec->build([ qw(RMBUILD RMSOURCE) ]) == 0, "simulate cleaning spec, source, build");

ok(defined($h = $spec->srcheader()), "Geting source header after build");
ok($h->queryformat("%{NAME}") eq "test-rpm", "can querying header give by spec");
is($h->tag("URL"), "http://rpm4.zarb.org/", "can get url give by spec");

my ($bh) = $spec->binheader();
ok(defined($bh), "Can get binary header from spec");
ok($bh->queryformat("%{NAME}") eq "test-rpm", "can querying header give by spec");

