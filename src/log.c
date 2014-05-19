#include "log.h"

int log_init(const char* conf_path)
{
    int rc = zlog_init(conf_path);
    if (rc)
    {
        fprintf(stderr, "init log file failed!\n");
        return -1;
    }
    if (!(cat = zlog_get_category("beansdb")))
    {
        fprintf(stderr, "get category beansdb failed!\n");
        zlog_fini();
        return -1;
    }
    return 0;
}

void log_finish()
{
    zlog_fini();
    return;
}


