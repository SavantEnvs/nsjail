// Fuzz nsjail's nstun userspace NAT stack with IP frames written by the jailed guest
// (the untrusted side). Path: nstun_init_parent -> networkLoop -> handle_tun_frame ->
// handle_ip4/6 -> tcp/udp/icmp handlers + policy evaluation.
//
// Input: byte 0 selects the rule set the frames are matched against
//   (0: REDIRECT, 1: ENCAP_SOCKS5, 2: ENCAP_CONNECT, 3: REJECT, else no rules/ALLOW),
// then a sequence of frames, each a 2-byte big-endian length followed by that many
// bytes of raw IPv4/IPv6 packet. Every flow is pointed at a loopback sink, so no
// guest packet ever reaches a real remote host.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include "nstun_driver.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
	logs::setLogLevel(logs::FATAL);
	mayhem_nstun::sink();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 1) return 0;
	const uint8_t mode = data[0];
	data++;
	size--;

	std::vector<std::vector<uint8_t>> frames;
	while (size >= 2) {
		size_t len = ((size_t)data[0] << 8) | data[1];
		data += 2;
		size -= 2;
		if (len > size) len = size;
		frames.emplace_back(data, data + len);
		data += len;
		size -= len;
	}

	auto nsj = std::make_unique<nsj_t>();
	auto* un = nsj->njc.mutable_user_net();
	un->set_backend(nsjail::NsJailConfig_UserNet::NSTUN);
	const uint16_t port = mayhem_nstun::sink().port;
	using R = nsjail::NsJailConfig_UserNet_NstunRule;
	R::Action act;
	switch (mode) {
	case 0: act = R::REDIRECT; break;
	case 1: act = R::ENCAP_SOCKS5; break;
	case 2: act = R::ENCAP_CONNECT; break;
	case 3: act = R::REJECT; break;
	default: act = R::ALLOW; break;
	}
	if (act != R::ALLOW) {
		/* An ICMP rule first so ICMP echo is answered/redirected locally too. */
		R* icmp = un->add_rule4();
		icmp->set_proto(R::ICMP);
		icmp->set_action(act == R::REJECT ? R::REJECT : R::REDIRECT);
		icmp->set_redirect_ip("127.0.0.1");
		R* r4 = un->add_rule4();
		r4->set_action(act);
		r4->set_redirect_ip("127.0.0.1");
		r4->set_redirect_port(port);
		R* r6 = un->add_rule6();
		r6->set_action(act);
		r6->set_redirect_ip(act == R::REDIRECT ? "::1" : "127.0.0.1");
		r6->set_redirect_port(port);
	} else {
		/* No catch-all redirect: flows still must not leave the host, so drop them
		 * after the stack has parsed them. */
		R* r4 = un->add_rule4();
		r4->set_action(R::DROP);
		R* r6 = un->add_rule6();
		r6->set_action(R::DROP);
	}

	mayhem_nstun::run(nsj.get(), frames);
	return 0;
}
