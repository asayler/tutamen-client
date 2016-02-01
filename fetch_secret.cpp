#include <stdio.h>
#include <stdlib.h>

#define COL_UID "c03871cc-fa33-4634-8a1e-5a541227f633"
#define SEC_UID "360977f3-4445-4299-b091-f42f2a0e5a1e"

main()
{
    FILE* fpipe;
    char command[] = "tutamencli.py util fetch_secret " COL_UID " " SEC_UID;
    char secret[256];

    if ( !(fpipe = (FILE*) popen(command, "r")) )
        {  // If fpipe is NULL
            perror("Problems with pipe");
            exit(1);
        }

    fgets(secret, sizeof(secret), fpipe);
    printf("%s", secret);

    pclose(fpipe);
}
