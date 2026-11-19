// Fuzz the kafel seccomp-policy compiler through nsjail's own interface: the
// `seccomp_string` config field (also --seccomp_string) compiled by sandbox::preparePolicy().
#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "logs.h"
#include "nsjail.h"
#include "sandbox.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
	logs::setLogLevel(logs::FATAL);
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	auto nsj = std::make_unique<nsj_t>();
	/* preparePolicy treats an empty seccomp_string list as "no policy". */
	nsj->njc.add_seccomp_string(std::string((const char*)data, size));
	(void)sandbox::preparePolicy(nsj.get());
	sandbox::closePolicy(nsj.get());
	return 0;
}
