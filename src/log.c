#include "log.h"

zlog_category_t *cat;

int log_init(const char *conf_path)
{
    int rc = zlog_init(conf_path);
    if (rc)
    {
        fprintf(stderr, "init log file %s failed, please check zlog user guide!\n", conf_path);
        return -1;
    }
    if (!(cat = zlog_get_category("beansdb")))
    {
        fprintf(stderr, "fail to find category beansdb in %s!\n", conf_path);
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


