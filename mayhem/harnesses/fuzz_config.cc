// Fuzz nsjail's config-file path: config::parseFile() (TextProto or ProtoJSON ->
// parseInternal: rlimits, mounts, id maps, caps, env, seccomp, user_net), then the
// two consumers of the parsed config that turn its strings into kernel-facing state
// without needing privileges: sandbox::preparePolicy() (kafel seccomp policy) and
// nstun_init_parent() (user_net rule4/rule6 parsing: CIDRs, port ranges, redirect
// targets, HOST_TO_GUEST listeners). Same order nsjail itself uses (-C <file>).
//
// Kept across inputs on purpose: config::parseFile's static TextProto/JSON messages
// (both are re-parsed from scratch each call). Reset per input: log fd/level, which a
// config can change with log_fd/log_file/log_level.
//
// log_file: parseInternal() hands it to logs::logFile(), which open(O_CREAT|O_APPEND)s
// the path, so a fuzzed config could create/append to any file the fuzzer can write.
// The harness parses the input the way parseFile() does (ProtoJSON and TextProto, exactly
// one must succeed); when it carries log_file, that value is replaced by a fixed path in
// the scratch dir and the message is re-serialized in the same format before parseFile()
// reads it. The scratch log is unlinked after every input. Inputs without log_file are
// passed byte-for-byte. log_fd is left as is: logs::logFile() only dup()s that fd and the
// harness restores stderr after each input.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>

#include <memory>
#include <string>

#include "config.h"
#include "nstun_driver.h"
#include "sandbox.h"

static std::string g_path;
static std::string g_log; /* scratch replacement for a fuzzed log_file */

/* Returns the bytes parseFile() should read: the input, or the input with log_file sandboxed. */
static std::string sandboxLogFile(const uint8_t* data, size_t size) {
	std::string conf((const char*)data, size);
	static nsjail::NsJailConfig json_nsc, text_nsc;
	bool json_ok = google::protobuf::util::JsonStringToMessage(conf, &json_nsc).ok();
	bool text_ok = google::protobuf::TextFormat::ParseFromString(conf, &text_nsc);
	if (json_ok == text_ok) return conf; /* parseFile() rejects it before parseInternal() */
	nsjail::NsJailConfig& m = json_ok ? json_nsc : text_nsc;
	if (!m.has_log_file()) return conf;
	m.set_log_file(g_log);
	std::string out;
	if (json_ok) {
		if (!google::protobuf::util::MessageToJsonString(m, &out).ok()) abort();
	} else {
		if (!google::protobuf::TextFormat::PrintToString(m, &out)) abort();
	}
	return out;
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
	logs::setLogLevel(logs::FATAL);
	const char* tmp = getenv("TMPDIR");
	std::string t = std::string((tmp && *tmp) ? tmp : "/tmp") + "/nsjail-config-XXXXXX";
	int fd = mkstemp(t.data());
	if (fd == -1) abort();
	close(fd);
	g_path = t;
	g_log = t + ".log";
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	std::string conf = sandboxLogFile(data, size);
	FILE* f = fopen(g_path.c_str(), "wb");
	if (!f) abort();
	fwrite(conf.data(), 1, conf.size(), f);
	fclose(f);

	auto nsj = std::make_unique<nsj_t>();
	bool ok = config::parseFile(nsj.get(), g_path.c_str());
	logs::logFile("", STDERR_FILENO);
	unlink(g_log.c_str());
	logs::setLogLevel(logs::FATAL);
	if (!ok) return 0;

	(void)sandbox::preparePolicy(nsj.get());
	sandbox::closePolicy(nsj.get());

	if (nsj->njc.has_user_net()) {
		/* No guest frames: only the rule set is parsed and listeners are set up/torn down. */
		mayhem_nstun::run(nsj.get(), {});
	}
	return 0;
}
