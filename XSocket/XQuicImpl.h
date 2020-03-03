/*
 * Copyright: 7thTool Open Source <i7thTool@qq.com>
 * All rights reserved.
 * 
 * Author	: Scott
 * Email	：i7thTool@qq.com
 * Blog		: http://blog.csdn.net/zhangzq86
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _H_XQUICK_IMPL_H_
#define _H_XQUICK_IMPL_H_

#include "XSocketImpl.h"
#include "XCodec.h"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

#include <vector>
#include <deque>
#include <map>
#include <string_view>
#include <sstream>
#include <strstream>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

namespace XSocket {

/*!
 *	@brief QuickSocketT 定义.
 *
 *	封装QuickSocketT，实现Udp Quick收发数据功能
 */
template<class TBase>
class QuickSocketT : public TBase
{
	typedef QuickSocketT<TBase> This;
	typedef TBase Base;
protected:
  std::map<std::string, std::unique_ptr<Handler>> handlers_;
  // ctos_ is a mapping between client's initial destination
  // connection ID, and server source connection ID.
  std::map<std::string, std::string> ctos_;
  std::vector<Endpoint> endpoints_;
  ngtcp2_crypto_aead token_aead_;
  ngtcp2_crypto_md token_md_;
  std::array<uint8_t, TOKEN_SECRETLEN> token_secret_;
public:
	QuickSocketT()
	{
			
	}

	~QuickSocketT() 
	{
		
	}

protected:
	//
	//解析数据包
	virtual int ParseBuf(const char* lpBuf, int & nBufLen, const SockAddr & stAddr) { 
		ngtcp2_pkt_hd hd;
		uint32_t version;
		const uint8_t *dcid, *scid;
		size_t dcidlen, scidlen;
		if (auto rv = ngtcp2_pkt_decode_version_cid(&version, &dcid, &dcidlen,
													&scid, &scidlen, lpBuf,
													nBufLen, NGTCP2_SV_SCIDLEN);
			rv != 0) {
		if (rv == 1) {
			send_version_negotiation(version, scid, scidlen, dcid, dcidlen, ep,
									&su.sa, addrlen);
			continue;
		}
		std::cerr << "Could not decode version and CID from QUIC packet header: "
					<< ngtcp2_strerror(rv) << std::endl;
		continue;
		}

		auto dcid_key = util::make_cid_key(dcid, dcidlen);

		auto handler_it = handlers_.find(dcid_key);
		if (handler_it == std::end(handlers_)) {
		auto ctos_it = ctos_.find(dcid_key);
		if (ctos_it == std::end(ctos_)) {
			if (auto rv = ngtcp2_accept(&hd, buf.data(), nread); rv == -1) {
			if (!config.quiet) {
				std::cerr << "Unexpected packet received: length=" << nread
						<< std::endl;
			}
			continue;
			} else if (rv == 1) {
			if (!config.quiet) {
				std::cerr << "Unsupported version: Send Version Negotiation"
						<< std::endl;
			}
			send_version_negotiation(hd.version, hd.scid.data, hd.scid.datalen,
									hd.dcid.data, hd.dcid.datalen, ep, &su.sa,
									addrlen);
			continue;
			}

			ngtcp2_cid ocid;
			ngtcp2_cid *pocid = nullptr;
			switch (hd.type) {
			case NGTCP2_PKT_INITIAL:
			if (config.validate_addr || hd.tokenlen) {
				std::cerr << "Perform stateless address validation" << std::endl;
				if (hd.tokenlen == 0 ||
					verify_token(&ocid, &hd, &su.sa, addrlen) != 0) {
				send_retry(&hd, ep, &su.sa, addrlen);
				continue;
				}
				pocid = &ocid;
			}
			break;
			case NGTCP2_PKT_0RTT:
			send_retry(&hd, ep, &su.sa, addrlen);
			continue;
			}

			auto h = std::make_unique<Handler>(loop_, ssl_ctx_, this, &hd.dcid);
			if (h->init(ep, &su.sa, addrlen, &hd.scid, &hd.dcid, pocid, hd.token,
						hd.tokenlen, hd.version) != 0) {
			continue;
			}

			switch (h->on_read(ep, &su.sa, addrlen, buf.data(), nread)) {
			case 0:
			break;
			case NGTCP2_ERR_RETRY:
			send_retry(&hd, ep, &su.sa, addrlen);
			continue;
			default:
			continue;
			}

			switch (h->on_write()) {
			case 0:
			case NETWORK_ERR_SEND_BLOCKED:
			break;
			default:
			continue;
			}

			auto scid = h->scid();
			auto scid_key = util::make_cid_key(scid);
			ctos_.emplace(dcid_key, scid_key);

			auto pscid = h->pscid();
			if (pscid->datalen) {
			auto pscid_key = util::make_cid_key(pscid);
			ctos_.emplace(pscid_key, scid_key);
			}

			handlers_.emplace(scid_key, std::move(h));
			continue;
		}
		if (!config.quiet) {
			std::cerr << "Forward CID=" << util::format_hex((*ctos_it).first)
					<< " to CID=" << util::format_hex((*ctos_it).second)
					<< std::endl;
		}
		handler_it = handlers_.find((*ctos_it).second);
		assert(handler_it != std::end(handlers_));
		}

		auto h = (*handler_it).second.get();
		if (ngtcp2_conn_is_in_closing_period(h->conn())) {
		// TODO do exponential backoff.
		switch (h->send_conn_close()) {
		case 0:
		case NETWORK_ERR_SEND_BLOCKED:
			break;
		default:
			remove(h);
		}
		continue;
		}
		if (h->draining()) {
		continue;
		}

		if (auto rv = h->on_read(ep, &su.sa, addrlen, buf.data(), nread); rv != 0) {
		if (rv != NETWORK_ERR_CLOSE_WAIT) {
			remove(h);
		}
		continue;
		}

		h->signal_write();
		return SOCKET_PACKET_FLAG_COMPLETE; }
	}

	return 0;
	}

	namespace {
	uint32_t generate_reserved_version(const sockaddr *sa, socklen_t salen,
									uint32_t version) {
	uint32_t h = 0x811C9DC5u;
	const uint8_t *p = (const uint8_t *)sa;
	const uint8_t *ep = p + salen;
	for (; p != ep; ++p) {
		h ^= *p;
		h *= 0x01000193u;
	}
	version = htonl(version);
	p = (const uint8_t *)&version;
	ep = p + sizeof(version);
	for (; p != ep; ++p) {
		h ^= *p;
		h *= 0x01000193u;
	}
	h &= 0xf0f0f0f0u;
	h |= 0x0a0a0a0au;
	return h;
	}
	} // namespace

	int send_version_negotiation(uint32_t version, const uint8_t *dcid,
										size_t dcidlen, const uint8_t *scid,
										size_t scidlen, Endpoint &ep,
										const sockaddr *sa, socklen_t salen) {
	Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
	std::array<uint32_t, 2> sv;

	sv[0] = generate_reserved_version(sa, salen, version);
	sv[1] = NGTCP2_PROTO_VER;

	auto nwrite = ngtcp2_pkt_write_version_negotiation(
		buf.wpos(), buf.left(),
		std::uniform_int_distribution<uint8_t>(
			0, std::numeric_limits<uint8_t>::max())(randgen),
		dcid, dcidlen, scid, scidlen, sv.data(), sv.size());
	if (nwrite < 0) {
		std::cerr << "ngtcp2_pkt_write_version_negotiation: "
				<< ngtcp2_strerror(nwrite) << std::endl;
		return -1;
	}

	buf.push(nwrite);

	Address remote_addr;
	remote_addr.len = salen;
	memcpy(&remote_addr.su.sa, sa, salen);

	if (send_packet(ep, remote_addr, buf.rpos(), buf.size(), 0) !=
		NETWORK_ERR_OK) {
		return -1;
	}

	return 0;
	}

	int send_retry(const ngtcp2_pkt_hd *chd, Endpoint &ep,
						const sockaddr *sa, socklen_t salen) {
	std::array<char, NI_MAXHOST> host;
	std::array<char, NI_MAXSERV> port;

	if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
								port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
		rv != 0) {
		std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
		return -1;
	}

	if (!config.quiet) {
		std::cerr << "Sending Retry packet to [" << host.data()
				<< "]:" << port.data() << std::endl;
	}

	std::array<uint8_t, 256> token;
	size_t tokenlen = token.size();

	if (generate_token(token.data(), tokenlen, sa, salen, &chd->dcid) != 0) {
		return -1;
	}

	if (!config.quiet) {
		std::cerr << "Generated address validation token:" << std::endl;
		util::hexdump(stderr, token.data(), tokenlen);
	}

	Buffer buf{NGTCP2_MAX_PKTLEN_IPV4};
	ngtcp2_pkt_hd hd;

	hd.version = chd->version;
	hd.flags = NGTCP2_PKT_FLAG_LONG_FORM;
	hd.type = NGTCP2_PKT_RETRY;
	hd.pkt_num = 0;
	hd.token = nullptr;
	hd.tokenlen = 0;
	hd.len = 0;
	hd.dcid = chd->scid;
	hd.scid.datalen = NGTCP2_SV_SCIDLEN;
	auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
	std::generate(hd.scid.data, hd.scid.data + hd.scid.datalen,
					[&dis]() { return dis(randgen); });

	auto nwrite = ngtcp2_pkt_write_retry(buf.wpos(), buf.left(), &hd, &chd->dcid,
										token.data(), tokenlen);
	if (nwrite < 0) {
		std::cerr << "ngtcp2_pkt_write_retry: " << ngtcp2_strerror(nwrite)
				<< std::endl;
		return -1;
	}

	buf.push(nwrite);

	Address remote_addr;
	remote_addr.len = salen;
	memcpy(&remote_addr.su.sa, sa, salen);

	if (send_packet(ep, remote_addr, buf.rpos(), buf.size(), 0) !=
		NETWORK_ERR_OK) {
		return -1;
	}

	return 0;
	}

	int derive_token_key(uint8_t *key, size_t &keylen, uint8_t *iv,
								size_t &ivlen, const uint8_t *rand_data,
								size_t rand_datalen) {
	std::array<uint8_t, 32> secret;

	if (ngtcp2_crypto_hkdf_extract(secret.data(), secret.size(), &token_md_,
									token_secret_.data(), token_secret_.size(),
									rand_data, rand_datalen) != 0) {
		return -1;
	}

	keylen = ngtcp2_crypto_aead_keylen(&token_aead_);
	ivlen = ngtcp2_crypto_packet_protection_ivlen(&token_aead_);

	if (ngtcp2_crypto_derive_packet_protection_key(key, iv, nullptr, &token_aead_,
													&token_md_, secret.data(),
													secret.size()) != 0) {
		return -1;
	}

	return 0;
	}

	int generate_rand_data(uint8_t *buf, size_t len) {
	std::array<uint8_t, 16> rand;
	std::array<uint8_t, 32> md;
	auto dis = std::uniform_int_distribution<uint8_t>(0, 255);
	std::generate_n(rand.data(), rand.size(), [&dis]() { return dis(randgen); });

	auto ctx = EVP_MD_CTX_new();
	if (ctx == nullptr) {
		return -1;
	}

	auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

	unsigned int mdlen = md.size();
	if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
		!EVP_DigestUpdate(ctx, rand.data(), rand.size()) ||
		!EVP_DigestFinal_ex(ctx, md.data(), &mdlen)) {
		return -1;
	}

	std::copy_n(std::begin(md), len, buf);
	return 0;
	}

	int generate_token(uint8_t *token, size_t &tokenlen, const sockaddr *sa,
							socklen_t salen, const ngtcp2_cid *ocid) {
	std::array<uint8_t, 4096> plaintext;

	uint64_t t = std::chrono::duration_cast<std::chrono::nanoseconds>(
					std::chrono::system_clock::now().time_since_epoch())
					.count();

	auto p = std::begin(plaintext);
	p = std::copy_n(reinterpret_cast<const uint8_t *>(sa), salen, p);
	// Host byte order
	p = std::copy_n(reinterpret_cast<uint8_t *>(&t), sizeof(t), p);
	p = std::copy_n(ocid->data, ocid->datalen, p);

	std::array<uint8_t, TOKEN_RAND_DATALEN> rand_data;
	std::array<uint8_t, 32> key, iv;
	auto keylen = key.size();
	auto ivlen = iv.size();

	if (generate_rand_data(rand_data.data(), rand_data.size()) != 0) {
		return -1;
	}
	if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data.data(),
						rand_data.size()) != 0) {
		return -1;
	}

	auto plaintextlen = std::distance(std::begin(plaintext), p);
	if (ngtcp2_crypto_encrypt(token, &token_aead_, plaintext.data(), plaintextlen,
								key.data(), iv.data(), ivlen,
								reinterpret_cast<const uint8_t *>(sa),
								salen) != 0) {
		return -1;
	}

	tokenlen = plaintextlen + ngtcp2_crypto_aead_taglen(&token_aead_);
	memcpy(token + tokenlen, rand_data.data(), rand_data.size());
	tokenlen += rand_data.size();

	return 0;
	}

	int verify_token(ngtcp2_cid *ocid, const ngtcp2_pkt_hd *hd,
							const sockaddr *sa, socklen_t salen) {
	std::array<char, NI_MAXHOST> host;
	std::array<char, NI_MAXSERV> port;

	if (auto rv = getnameinfo(sa, salen, host.data(), host.size(), port.data(),
								port.size(), NI_NUMERICHOST | NI_NUMERICSERV);
		rv != 0) {
		std::cerr << "getnameinfo: " << gai_strerror(rv) << std::endl;
		return -1;
	}

	if (!config.quiet) {
		std::cerr << "Verifying token from [" << host.data() << "]:" << port.data()
				<< std::endl;
	}

	if (!config.quiet) {
		std::cerr << "Received address validation token:" << std::endl;
		util::hexdump(stderr, hd->token, hd->tokenlen);
	}

	if (hd->tokenlen < TOKEN_RAND_DATALEN) {
		if (!config.quiet) {
		std::cerr << "Token is too short" << std::endl;
		}
		return -1;
	}

	auto rand_data = hd->token + hd->tokenlen - TOKEN_RAND_DATALEN;
	auto ciphertext = hd->token;
	auto ciphertextlen = hd->tokenlen - TOKEN_RAND_DATALEN;

	std::array<uint8_t, 32> key, iv;
	auto keylen = key.size();
	auto ivlen = iv.size();

	if (derive_token_key(key.data(), keylen, iv.data(), ivlen, rand_data,
						TOKEN_RAND_DATALEN) != 0) {
		return -1;
	}

	std::array<uint8_t, 4096> plaintext;

	if (ngtcp2_crypto_decrypt(plaintext.data(), &token_aead_, ciphertext,
								ciphertextlen, key.data(), iv.data(), ivlen,
								reinterpret_cast<const uint8_t *>(sa),
								salen) != 0) {
		if (!config.quiet) {
		std::cerr << "Could not decrypt token" << std::endl;
		}
		return -1;
	}

	assert(ciphertextlen >= ngtcp2_crypto_aead_taglen(&token_aead_));

	auto plaintextlen = ciphertextlen - ngtcp2_crypto_aead_taglen(&token_aead_);
	if (plaintextlen < salen + sizeof(uint64_t)) {
		if (!config.quiet) {
		std::cerr << "Bad token construction" << std::endl;
		}
		return -1;
	}

	auto cil = plaintextlen - salen - sizeof(uint64_t);
	if (cil != 0 && (cil < NGTCP2_MIN_CIDLEN || cil > NGTCP2_MAX_CIDLEN)) {
		if (!config.quiet) {
		std::cerr << "Bad token construction" << std::endl;
		}
		return -1;
	}

	if (memcmp(plaintext.data(), sa, salen) != 0) {
		if (!config.quiet) {
		std::cerr << "Client address does not match" << std::endl;
		}
		return -1;
	}

	uint64_t t;
	memcpy(&t, plaintext.data() + salen, sizeof(uint64_t));

	uint64_t now = std::chrono::duration_cast<std::chrono::nanoseconds>(
						std::chrono::system_clock::now().time_since_epoch())
						.count();

	// Allow 10 seconds window
	if (t + 10ULL * NGTCP2_SECONDS < now) {
		if (!config.quiet) {
		std::cerr << "Token has been expired" << std::endl;
		}
		return -1;
	}

	ngtcp2_cid_init(ocid, plaintext.data() + salen + sizeof(uint64_t), cil);

	return 0;
	}

	int send_packet(Endpoint &ep, const Address &remote_addr,
							const uint8_t *data, size_t datalen, size_t gso_size,
							ev_io *wev) {
	if (debug::packet_lost(config.tx_loss_prob)) {
		if (!config.quiet) {
		std::cerr << "** Simulated outgoing packet loss **" << std::endl;
		}
		return NETWORK_ERR_OK;
	}

	iovec msg_iov;
	msg_iov.iov_base = const_cast<uint8_t *>(data);
	msg_iov.iov_len = datalen;

	msghdr msg{};
	msg.msg_name = const_cast<sockaddr *>(&remote_addr.su.sa);
	msg.msg_namelen = remote_addr.len;
	msg.msg_iov = &msg_iov;
	msg.msg_iovlen = 1;

	#if NGTCP2_ENABLE_UDP_GSO
	std::array<uint8_t, CMSG_SPACE(sizeof(uint16_t))> msg_ctrl{};
	if (gso_size && datalen > gso_size) {
		msg.msg_control = msg_ctrl.data();
		msg.msg_controllen = msg_ctrl.size();

		auto cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = SOL_UDP;
		cm->cmsg_type = UDP_SEGMENT;
		cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
		*(reinterpret_cast<uint16_t *>(CMSG_DATA(cm))) = gso_size;
	}
	#endif // NGTCP2_ENABLE_UDP_GSO

	ssize_t nwrite = 0;

	do {
		nwrite = sendmsg(ep.fd, &msg, 0);
	} while (nwrite == -1 && errno == EINTR);

	if (nwrite == -1) {
		std::cerr << "sendmsg: " << strerror(errno) << std::endl;
		// TODO We have packet which is expected to fail to send (e.g.,
		// path validation to old path).
		return NETWORK_ERR_OK;
	}

	if (!config.quiet) {
		std::cerr << "Sent packet: local="
				<< util::straddr(&ep.addr.su.sa, ep.addr.len) << " remote="
				<< util::straddr(&remote_addr.su.sa, remote_addr.len) << " "
				<< nwrite << " bytes" << std::endl;
	}

	return NETWORK_ERR_OK;
	}

	void associate_cid(const ngtcp2_cid *cid, Handler *h) {
	ctos_.emplace(util::make_cid_key(cid), util::make_cid_key(h->scid()));
	}

	void dissociate_cid(const ngtcp2_cid *cid) {
	ctos_.erase(util::make_cid_key(cid));
	}

	void remove(const Handler *h) {
	ctos_.erase(util::make_cid_key(h->rcid()));
	ctos_.erase(util::make_cid_key(h->pscid()));

	auto conn = h->conn();
	std::vector<ngtcp2_cid> cids(ngtcp2_conn_get_num_scid(conn));
	ngtcp2_conn_get_scid(conn, cids.data());

	for (auto &cid : cids) {
		ctos_.erase(util::make_cid_key(&cid));
	}

	handlers_.erase(util::make_cid_key(h->scid()));
	}

};

}

#endif//_H_XHTTP_IMPL_H_