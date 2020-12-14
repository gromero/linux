// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020, Gustavo Romero, IBM Corp.
 *
 * This test checks if when TM is not supported by the OS indeed it's not
 * possible to start a TM transaction. Moreover, when trying to start a new
 * transaction the user gets an illegal instruction, which is the correct
 * behavior in that case, instead of any other signal, like SIGSEGV etc.
 *
 * Since firmware can change the TM instruction behavior in many ways, it's good
 * to have a test to check if TM is properly disabled when the OS advertises
 * that TM is not available in userspace.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "utils.h"
#include "tm.h"

void illegal_signal_handler(int signo_notused, siginfo_t *si_notused, void *uc_notused)
{
	exit(EXIT_SUCCESS);
}

int tm_no_tm_test(void)
{
	struct sigaction illegal_sa;

	SKIP_IF(have_htm());

	illegal_sa.sa_flags = SA_SIGINFO;
	illegal_sa.sa_sigaction = illegal_signal_handler;

	sigaction(SIGILL, &illegal_sa, NULL);

	/* It must cause a SIGILL since TM is not supported by the OS */
	asm("tbegin.;");

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	return test_harness(tm_no_tm_test, "tm_no_tm_test");
}
