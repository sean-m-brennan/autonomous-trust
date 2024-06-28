/**
 * Copyright (C) 2024 t5
 */
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <unistd.h>

#define ULOG_TAG autonomous_trust
#include <ulog.h>
ULOG_DECLARE_TAG(ULOG_TAG);

atomic_bool run;

static void sig_handler(int sig)
{
	atomic_store(&run, false);
}

int main(int argc, char *argv[])
{
	/* Initialisation code
	 *
	 * The service is automatically started by the drone when the mission is
	 * loaded.
	 */
	ULOGI("Hello from autonomous_trust");
	atomic_init(&run, true);
	signal(SIGTERM, sig_handler);

	/* Loop code
	 *
	 * The service is assumed to run an infinite loop, and termination
	 * requests are handled via a SIGTERM signal.
	 * If your service exits before this SIGTERM is sent, it will be
	 * considered as a crash, and the system will relaunch the service.
	 * If this happens too many times, the system will no longer start the
	 * service.
	 */
	while (atomic_load(&run)) {
		ULOGI("Running ...");
		sleep(1);
	}

	/* Cleanup code
	 *
	 * When stopped by a SIGTERM, a service can use a short amount of time
	 * for cleanup (typically closing opened files and ensuring that the
	 * written data is coherent).
	 */
	ULOGI("Cleaning up from autonomous_trust");
	return 0;
}