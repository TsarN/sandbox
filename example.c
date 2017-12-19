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
	cfg.s_stdin = "";
	cfg.time_limit = 1000;
	cfg.wall_time_limit = 5000;
	cfg.mem_limit = 256 * 1024 * 1024;
	cfg.debug = true;
	sandbox_result_t res = sandbox_run(&cfg);
	printf("Got result:\n%s", res.s_stdout);
	return 0;
}