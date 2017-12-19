#ifndef _SANDBOX_H_
#define _SANDBOX_H_

#include <stdbool.h>


typedef struct {
	char *path;
	char **args;
	char **env;

	bool use_env;
	bool use_dup; 
	long time_limit; /* milliseconds */
	long wall_time_limit; /* milliseconds */
	long mem_limit; /* bytes */

	int fd_stdin;
	int fd_stdout;
	int fd_stderr;

	bool debug;
} sandbox_config_t;

typedef struct {
	int verdict;
	int exit_code;
	long cpu_time; /* milliseconds */
	long mem_usage; /* bytes */
} sandbox_result_t;

#define ER_OK   0
#define ER_TL   1
#define ER_ML   2
#define ER_RT   3
#define ER_WT   4
#define ER_SE   5
#define ER_FAIL 6

sandbox_result_t sandbox_run(const sandbox_config_t*);


#endif /* _SANDBOX_H_ */
