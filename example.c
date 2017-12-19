#include <stdio.h>
#include "sandbox.h"

char *env[] = {
	NULL
};

static const char *sandbox_results[] = {
	"OK",
	"TL",
	"ML",
	"RT",
	"WT",
	"SE",
	"FAIL"
};

int main(int argc, char *argv[]) {
	sandbox_config_t cfg;
	cfg.path = argv[1];
	cfg.args = argv + 1;
	cfg.env = env;
	cfg.use_env = true;
	cfg.use_dup = false;
	cfg.time_limit = 1000;
	cfg.wall_time_limit = 5000;
	cfg.mem_limit = 256 * 1024 * 1024;
	cfg.debug = true;
	sandbox_run(&cfg);
	return 0;
}