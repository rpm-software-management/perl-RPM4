/* $Id$ */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#undef Fflush
#undef Mkdir
#undef Stat

#include <rpm/rpmcli.h>

#include "RPM4.h"

/* Hight level function */
int rpmsign(char *passphrase, const char *rpm) {
    QVA_t qva = &rpmQVKArgs;
    ARGV_t file = NULL;

    argvAdd(&file, rpm);

    qva->qva_mode = RPMSIGN_ADD_SIGNATURE;
    qva->passPhrase = passphrase;
    
    return rpmcliSign(NULL, qva, file);
}

