#include <linux/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "./utils.h"

#define die_fmt(str, ...) ({						\
		fprintf(stderr, color(BRED, "[ERROR] "));	\
		fprintf(stderr, (str), ##__VA_ARGS__);		\
		puts("");									\
		exit(-1);									\
	})


static void sig_handler(int sig) {
	if (sig==SIGINT || sig==SIGQUIT) {
		pr("goodbye");
		exit(0);
	}
}

void main() {
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		die_fmt("failed to register SIGINT");

	if (signal(SIGQUIT, sig_handler)== SIG_ERR)
		die_fmt("failed to register SIGQUIT");

	while(1);
}