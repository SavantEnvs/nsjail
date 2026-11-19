// Drives nsjail's userspace network stack (nstun) through its public API:
// nstun_init_parent() receives the "TAP" fd over a unix socket (SCM_RIGHTS) exactly
// as it does from the jailed child, so we hand it one end of a SOCK_SEQPACKET pair
// (one read() == one IP frame, like a TUN device) and play the guest on the other.
#ifndef MAYHEM_NSTUN_DRIVER_H
#define MAYHEM_NSTUN_DRIVER_H

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include "logs.h"
#include "nsjail.h"
#include "nstun/nstun.h"
#include "util.h"

namespace mayhem_nstun {

/* Loopback sockets that REDIRECT/ENCAP rules point at, so guest flows never leave the host. */
struct Sink {
	int tcp4 = -1, udp4 = -1;
	uint16_t port = 0;
};

static inline Sink& sink() {
	static Sink s;
	if (s.tcp4 != -1) return s;
	s.tcp4 = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	struct sockaddr_in a = {};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	bind(s.tcp4, (struct sockaddr*)&a, sizeof(a));
	listen(s.tcp4, 1024);
	socklen_t l = sizeof(a);
	getsockname(s.tcp4, (struct sockaddr*)&a, &l);
	s.port = ntohs(a.sin_port);
	s.udp4 = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	bind(s.udp4, (struct sockaddr*)&a, sizeof(a));
	return s;
}

/* Throw away whatever earlier inputs left queued on the sink sockets. */
static inline void drain_sink() {
	Sink& s = sink();
	for (;;) {
		int c = accept4(s.tcp4, nullptr, nullptr, SOCK_CLOEXEC);
		if (c == -1) break;
		close(c);
	}
	char b[2048];
	while (recv(s.udp4, b, sizeof(b), MSG_DONTWAIT) > 0) {
	}
}

/*
 * Starts nstun for `nsj`, writes each frame to the guest side of the TAP, then
 * closes the guest's write side and waits until nstun has drained every frame and
 * exited its loop (it closes its TAP end on EOF), so each input is processed in full.
 * Returns false when nstun_init_parent() rejects the configuration.
 */
static inline bool run(nsj_t* nsj, const std::vector<std::vector<uint8_t>>& frames) {
	int tap[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, tap) == -1) return false;
	int sz = 1 << 20;
	setsockopt(tap[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	setsockopt(tap[1], SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	/* A real TUN fd is opened O_NONBLOCK (nstun_init_child). */
	fcntl(tap[1], F_SETFL, fcntl(tap[1], F_GETFL) | O_NONBLOCK);

	int ctl[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, ctl) == -1) {
		close(tap[0]);
		close(tap[1]);
		return false;
	}
	bool sent = util::sendFd(ctl[0], tap[1]);
	close(tap[1]);
	struct nstun_context_handle* handle = nullptr;
	bool ok = sent && nstun_init_parent(ctl[1], nsj, &handle);
	close(ctl[0]);
	close(ctl[1]);
	if (!ok) {
		close(tap[0]);
		return false;
	}

	char rbuf[70000];
	for (const auto& f : frames) {
		/* A zero-length datagram reads as EOF on the TAP; real TUN never delivers one. */
		if (f.empty()) continue;
		for (;;) {
			struct pollfd p = {.fd = tap[0], .events = POLLIN | POLLOUT, .revents = 0};
			if (poll(&p, 1, -1) == -1) continue;
			if (p.revents & POLLIN) (void)read(tap[0], rbuf, sizeof(rbuf));
			if (p.revents & (POLLERR | POLLHUP)) goto done;
			if (p.revents & POLLOUT) {
				(void)write(tap[0], f.data(), f.size());
				break;
			}
		}
	}
done:
	shutdown(tap[0], SHUT_WR);
	/* Replies nstun sends to the guest are read and dropped; EOF == loop exited. */
	while (read(tap[0], rbuf, sizeof(rbuf)) > 0) {
	}
	nstun_destroy_parent(handle);
	close(tap[0]);
	drain_sink();
	return true;
}

}  // namespace mayhem_nstun

#endif
