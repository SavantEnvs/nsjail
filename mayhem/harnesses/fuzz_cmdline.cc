// Fuzz nsjail's command line: cmdline::parseArgs() (getopt_long over every custom_opts
// entry: mount specs -R/-B/-T/-m, uid/gid maps -u/-g/-U/-G, rlimits, numeric options,
// macvlan, user_net, ...) followed by setupMounts/setupArgv/setupUsers, exactly as
// nsjail's main() does.
//
// Input: NUL-separated arguments (argv[0] = "nsjail" is prepended). Arguments that would
// make the process leave the fuzzing loop or touch arbitrary host files are dropped:
// -C/--config (covered by the `config` target), -l/--log, -L/--log_fd, -d/--daemon and
// -h/--help (including getopt_long's unique-prefix abbreviations and short-option clusters;
// see filterArgs). The --execute_fd descriptor parseArgs opens is closed after each input.
//
// nsjail reports some fatal parse errors with LOG_F, which ends in _exit(0xff) (logs.cc):
// nsjail's own "invalid value" exit, left as is (same as the `config` target).
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include "cmdline.h"
#include "logs.h"
#include "nsjail.h"

/* nsjail's own getopt_long optstring (cmdline.cc, parseArgs). */
static const char kOptString[] = "x:H:D:C:c:p:i:u:g:l:L:t:M:NdvqQeh?E:R:B:T:m:s:P:I:U:G:";
/* Short options to drop: config file, log file/fd, daemon (opens the default log file), help (exit). */
static const char kBadShort[] = "ClLdh";

static bool badLong(const std::string& a) {
	size_t eq = a.find('=');
	std::string name = a.substr(2, eq == std::string::npos ? std::string::npos : eq - 2);
	/* getopt_long accepts unique prefixes, so any prefix of a bad name is dropped too. */
	static const char* const bad[] = {"config", "log", "log_fd", "daemon", "help"};
	for (const char* b : bad) {
		if (strncmp(b, name.c_str(), name.size()) == 0) return true;
	}
	return false;
}

/*
 * Mirrors glibc getopt_long's scan: a short-option cluster is walked char by char with
 * nsjail's optstring, and stops at the first option that takes an argument (the rest of
 * the argument, or the next argument, is its value). Everything after a bare "--" is the
 * jailed command's argv and is never filtered. Long options are not looked up, so the
 * argument after one is still checked (conservative: at worst a value is dropped).
 */
static std::vector<std::string> filterArgs(std::vector<std::string> in) {
	std::vector<std::string> out;
	bool value_next = false, done = false;
	for (auto& a : in) {
		if (done || value_next || a.size() < 2 || a[0] != '-') {
			value_next = false;
			out.push_back(std::move(a));
			continue;
		}
		if (a == "--") {
			done = true;
			out.push_back(std::move(a));
			continue;
		}
		if (a[1] == '-') {
			if (!badLong(a)) out.push_back(std::move(a));
			continue;
		}
		bool bad = false;
		for (size_t i = 1; i < a.size(); i++) {
			char c = a[i];
			if (c != ':' && c != '\0' && strchr(kBadShort, c)) {
				bad = true;
				break;
			}
			const char* p = (c != ':' && c != '\0') ? strchr(kOptString, c) : nullptr;
			if (p && p[1] == ':') {
				if (i + 1 == a.size()) value_next = true;
				break; /* the rest of this argument is the option's value */
			}
		}
		if (!bad) out.push_back(std::move(a));
	}
	return out;
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
	logs::setLogLevel(logs::FATAL);
	/* Usage text and fatal messages go nowhere (-l/-L are filtered, so this sticks). */
	logs::logFile("/dev/null", STDERR_FILENO);
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	std::vector<std::string> raw;
	size_t start = 0;
	for (size_t i = 0; i <= size; i++) {
		if (i == size || data[i] == '\0') {
			raw.emplace_back((const char*)data + start, i - start);
			start = i + 1;
		}
	}
	std::vector<std::string> args = {"nsjail"};
	for (auto& a : filterArgs(std::move(raw))) args.push_back(std::move(a));
	if (args.size() > 256) args.resize(256);

	std::vector<char*> argv;
	for (auto& a : args) argv.push_back(a.data());
	argv.push_back(nullptr);

	optind = 0; /* full getopt re-initialisation (glibc) */
	opterr = 0;
	std::unique_ptr<nsj_t> nsj = cmdline::parseArgs((int)args.size(), argv.data());
	/*
	 * --execute_fd: setupArgv() opened the exec path into nsj->exec_fd (nsj_t has no
	 * destructor). A non-null result means that open() succeeded, so close it here or
	 * every such input leaks one fd.
	 */
	if (nsj && nsj->njc.exec_bin().exec_fd()) close(nsj->exec_fd);
	logs::setLogLevel(logs::FATAL);
	return 0;
}
