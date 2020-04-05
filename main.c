#include <clamav.h>
#include <stdio.h>
#include <string.h>

int main() {

    struct cl_engine *engine;
    struct cl_scan_options options;
    struct cl_stat dbstat;
    unsigned int sigs = 0;
    int ret;
    
    if((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
        printf("cl_init() error: %s\n", cl_strerror(ret));
        return 1;
    }

    if(!(engine = cl_engine_new())) {
        printf("Can't create new engine\n");
        return 1;
    }

    ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);

    if(ret != CL_SUCCESS) {
        printf("cl_load() error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return 1;
    }

    if((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        printf("cl_engine_compile() error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return 1;
    }

    memset(&dbstat, 0, sizeof(struct cl_stat));
    cl_statinidir(cl_retdbdir(), &dbstat);

    if(cl_statchkdir(&dbstat) == 1) {
        printf("Need to reload database\n");
    }

    options.general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_HEURISTICS;

    options.parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF |
                    CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3 | CL_SCAN_PARSE_XMLDOCS |
                    CL_SCAN_PARSE_MAIL | CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML |
                    CL_SCAN_PARSE_PE;
    options.heuristic = CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE | 
                        CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE |
                        CL_SCAN_HEURISTIC_ENCRYPTED_DOC | CL_SCAN_HEURISTIC_BROKEN |
                        CL_SCAN_HEURISTIC_EXCEEDS_MAX | 
                        CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH |
                        CL_SCAN_HEURISTIC_PHISHING_CLOAK | CL_SCAN_HEURISTIC_MACROS |
                        CL_SCAN_HEURISTIC_PARTITION_INTXN | CL_SCAN_HEURISTIC_STRUCTURED |
                        CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL |
                        CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;

    options.mail = CL_SCAN_MAIL_PARTIAL_MESSAGE;

    options.dev = 0;

    const char *virname;

    if((ret = cl_scanfile("/tmp/virus", &virname, NULL, engine, &options)) == CL_VIRUS) {
        printf("Virus detected: %s\n", virname);
    } else {
        printf("No virus detected.\n");
        if(ret != CL_CLEAN)
            printf("Error: %s\n", cl_strerror(ret));
    }
    
    cl_engine_free(engine);

    return 0;
}