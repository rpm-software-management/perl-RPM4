# $Id$

use strict;
use Test::More tests => 10;
use FindBin qw($Bin);
use RPM4;

my $htest = RPM4::Header->new("$Bin/test-rpm-1.0-1mdk.noarch.rpm");
isa_ok($htest, 'RPM4::Header', '$htest');

my $files = $htest->files();
isa_ok($files, 'RPM4::Header::Files', '$files');

is(
    $files->count(),
    1,
    "files count OK"
);
like(
    $files->filename(),
    qr!^/!,
    "filename OK"
);
like(
    $files->dirname(),
    qr!^/!,
    "dirname OK"
);
ok(defined($files->basename()), "Can get Files::basename()");
ok(defined($files->fflags()), "Can get Files::fflags()");
is(
    $files->md5(),
    "b9cb4e3dc1b8007e5c9678d1acecac47",
    "md5 is OK"
);
ok(!defined($files->link()), "Can get Files::link()");
ok(defined($files->mode()), "Can get Files::mode()");
