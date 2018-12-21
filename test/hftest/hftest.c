/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hftest.h"

#include <stdalign.h>
#include <stdint.h>

#include "hf/arch/vm/power_mgmt.h"

#include "hf/fdt.h"
#include "hf/memiter.h"
#include "hf/std.h"

alignas(4096) uint8_t kstack[4096];

HFTEST_ENABLE();

extern struct hftest_test hftest_begin[];
extern struct hftest_test hftest_end[];

static struct hftest_context global_context;

struct hftest_context *hftest_get_context(void)
{
	return &global_context;
}

static void json(void)
{
	struct hftest_test *test;
	const char *suite = NULL;
	size_t suites_in_image = 0;
	size_t tests_in_suite = 0;

	HFTEST_LOG("{");
	HFTEST_LOG("  \"suites\": [");
	for (test = hftest_begin; test < hftest_end; ++test) {
		if (test->suite != suite) {
			/* Close out previously open suite. */
			if (tests_in_suite) {
				HFTEST_LOG("      ]");
				HFTEST_LOG("    },");
			}
			/* Move onto new suite. */
			++suites_in_image;
			suite = test->suite;
			tests_in_suite = 0;
			HFTEST_LOG("    {");
			HFTEST_LOG("      \"name\": \"%s\",", test->suite);
		}
		if (test->kind == HFTEST_KIND_SET_UP) {
			HFTEST_LOG("      \"setup\": true,");
		}
		if (test->kind == HFTEST_KIND_TEAR_DOWN) {
			HFTEST_LOG("      \"teardown\": true,");
		}
		if (test->kind == HFTEST_KIND_TEST) {
			if (!tests_in_suite) {
				HFTEST_LOG("      \"tests\": [");
			}
			/*
			 * It's easier to put the comma at the start of the line
			 * than the end even
			 * though the JSON looks a bit funky.
			 */
			HFTEST_LOG("       %c\"%s\"",
				   tests_in_suite ? ',' : ' ', test->name);
			++tests_in_suite;
		}
	}
	if (tests_in_suite) {
		HFTEST_LOG("      ]");
		HFTEST_LOG("    }");
	}
	HFTEST_LOG("  ]");
	HFTEST_LOG("}");
}

static noreturn void abort(void)
{
	HFTEST_LOG("FAIL");
	shutdown();
}

static void run_test(hftest_test_fn set_up, hftest_test_fn test,
		     hftest_test_fn tear_down)
{
	/* Prepare the context. */
	struct hftest_context *ctx = hftest_get_context();
	memset(ctx, 0, sizeof(*ctx));
	ctx->abort = abort;

	/* Run any set up functions. */
	if (set_up) {
		set_up();
		if (ctx->failures) {
			abort();
		}
	}

	/* Run the test. */
	test();
	if (ctx->failures) {
		abort();
	}

	/* Run any tear down functions. */
	if (tear_down) {
		tear_down();
		if (ctx->failures) {
			abort();
		}
	}

	HFTEST_LOG("FINISHED");
}

static void run(struct memiter *args)
{
	struct memiter suite_name;
	struct memiter test_name;
	struct hftest_test *test;
	bool found_suite = false;
	const char *suite = NULL;
	hftest_test_fn suite_set_up = NULL;
	hftest_test_fn suite_tear_down = NULL;

	if (!memiter_parse_str(args, &suite_name)) {
		HFTEST_LOG("Unable to parse test suite.");
		return;
	}

	if (!memiter_parse_str(args, &test_name)) {
		HFTEST_LOG("Unable to parse test.");
		return;
	}

	for (test = hftest_begin; test < hftest_end; ++test) {
		/* Find the test suite. */
		if (found_suite) {
			if (test->suite != suite) {
				/* Test wasn't in the suite. */
				break;
			}
		} else {
			if (test->suite == suite) {
				/* This isn't the right suite so keep going. */
				continue;
			}
			/* Examine a new suite. */
			suite = test->suite;
			if (memiter_iseq(&suite_name, test->suite)) {
				found_suite = true;
			}
		}

		switch (test->kind) {
		/*
		 * The first entries in the suite are the set up and tear down
		 * functions.
		 */
		case HFTEST_KIND_SET_UP:
			suite_set_up = test->fn;
			break;
		case HFTEST_KIND_TEAR_DOWN:
			suite_tear_down = test->fn;
			break;
		/* Find the test. */
		case HFTEST_KIND_TEST:
			if (memiter_iseq(&test_name, test->name)) {
				run_test(suite_set_up, test->fn,
					 suite_tear_down);
				return;
			}
			break;
		default:
			/* Ignore other kinds. */
			break;
		}
	}

	HFTEST_LOG("Unable to find requested tests.");
}

static void help(void)
{
	HFTEST_LOG("usage:");
	HFTEST_LOG("");
	HFTEST_LOG("  help");
	HFTEST_LOG("");
	HFTEST_LOG("    Show this help.");
	HFTEST_LOG("");
	HFTEST_LOG("  json");
	HFTEST_LOG("");
	HFTEST_LOG(
		"    Print a directory of test suites and tests in "
		"JSON "
		"format.");
	HFTEST_LOG("");
	HFTEST_LOG("  run <suite> <test>");
	HFTEST_LOG("");
	HFTEST_LOG("    Run the named test from the named test suite.");
}

void kmain(const struct fdt_header *fdt)
{
	struct fdt_node n;
	const char *bootargs;
	uint32_t bootargs_size;
	struct memiter bootargs_iter;
	struct memiter command;

	if (!fdt_root_node(&n, fdt)) {
		HFTEST_LOG("FDT failed validation.");
		return;
	}

	if (!fdt_find_child(&n, "")) {
		HFTEST_LOG("Unable to find root node in FDT.");
		return;
	}

	if (!fdt_find_child(&n, "chosen")) {
		HFTEST_LOG("Unable to find 'chosen' node in FDT.");
		return;
	}

	if (!fdt_read_property(&n, "bootargs", &bootargs, &bootargs_size)) {
		HFTEST_LOG("Unable to read bootargs.");
		return;
	}

	/* Remove null terminator. */
	memiter_init(&bootargs_iter, bootargs, bootargs_size - 1);

	if (!memiter_parse_str(&bootargs_iter, &command)) {
		HFTEST_LOG("Unable to parse command.");
		return;
	}

	if (memiter_iseq(&command, "json")) {
		json();
		return;
	}

	if (memiter_iseq(&command, "run")) {
		run(&bootargs_iter);
		return;
	}

	help();
}