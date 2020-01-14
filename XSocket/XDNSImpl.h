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
#ifndef _H_XDNS_IMPL_H_
#define _H_XDNS_IMPL_H_

#include "XHttpImpl.h"
#include "XBuffer.h"

namespace XSocket {

namespace DNS {

#pragma pack(push, 1)

const size_t DNS_DEF_DATA_SIZE = (512 * 10);
const size_t DNS_MAX_CNAME_LEN = 256;
const size_t DNS_MAX_OPT_LEN = 256;

enum opcode_t 
{
	QUERY = 0,
	IQUERY = 1,
	STATUS = 2,
	NOTIFY = 4,
	UPDATE = 5,
};

enum rcode_t {
	NOERROR = 0,
	FORMERR = 1,
	SERVFAIL = 2,
	NXDOMAIN = 3,
	NOTIMP = 4,
	REFUSED = 5,
	YXDOMAIN = 6,
	YXRRSET = 7,
	NXRRSET = 8,
	NOTAUTH = 9,
	NOTZONE = 10,
};
    /*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      ID                       |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|QR|   opcode  |AA|TC|RD|RA|   z    |   rcode   |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                  Questions                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                  AnswerRRs                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|               AuthorityRRs                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|              AdditionalRRs                    |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/
struct head_t 
{
	uint16_t id;
    union {
        uint16_t flags;
        struct
        {
            uint16_t : 1 QR;     //0:query 1:response
            uint16_t : 4 opcode; //
            uint16_t : 1 AA;     //1:Authoritative Answer
            uint16_t : 1 TC;     //1:Truncation
            uint16_t : 1 RD;     //1:Recursion Desired
            uint16_t : 1 RA;     //1:Recursion Available
            uint16_t : 3 zero;   //
            uint16_t : 4 rcode;  //Response Code
        };
    };
	uint16_t Questions; //number of questions entries
	uint16_t AnswerRRs; //number of answers entries
	uint16_t AuthorityRRs; //number of Authoritative namesversers entries
	uint16_t AdditionalRRs; //number of addititional resource entries
};

const uint8_t MAX_NAME_LENGTH = (uint8_t)(-1);
const uint16_t MAX_DATA_LENGTH = (uint16_t)(-1);

struct str8_t
{
    uint8_t len;
    uint8_t str[0];
};

struct data16_t
{
    uint16_t len;
    uint8_t data[0];
};

enum type_t {
	A = 1,
	NS = 2,
	CNAME = 5,
	SOA = 6,
	PTR = 12,
	MX = 15,
	TXT = 16,
	AAAA = 28,
	SRV = 33,
	OPT = 41,
	SSHFP = 44,
	SPF = 99,
	AXFR = 252,
	ALL = 255
};

const size_t RR_A_LEN = 4;
const size_t RR_AAAA_LEN = 16;

enum class_t 
{
    IN = 1,
    ANY = 255 
};

//Queries/Questions
//Name + '\0' + Type(2) + Class(2)
    /*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                                               /
	/                      NAME                     /
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     CLASS                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/

//RRs
//Name + '\0' + Type(2) + Class(2) + TTL(4) + DataLength(2) + Data
    /*
	0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                                               |
	/                                               /
	/                      NAME                     /
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                      TYPE                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                     CLASS                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|                       TTL                     |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	|        DataLength     |           DATA        |
	+--+--+--+--+--+--+--+                          |
	/                                               /
	/                      DATA                     /
	|                                               |
	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	*/

enum rr_type_t 
{
	AN = 0,
	NS = 1,
	AD = 2,
	OPT = 3,
    MAX = 4,
};

struct soa_t {
	char mname[DNS_MAX_CNAME_LEN];
	char rname[DNS_MAX_CNAME_LEN];
	unsigned int serial;
	unsigned int refresh;
	unsigned int retry;
	unsigned int expire;
	unsigned int minimum;
};

enum opt_code_t
{ 
	ECS = 8, 
	TCP_KEEPALIVE = 11,
	ALL = 255 
};

const uint16_t OPT_ECS_FAMILY_IPV4 = 1;
const uint16_t OPT_ECS_FAMILY_IPV6 = 2;

/* OPT ECS */
struct opt_ecs_t {
	uint16_t family;
	uint8_t source_prefix;
	uint8_t scope_prefix;
	uint8_t addr[RR_AAAA_LEN];
};

struct opt_t {
	uint16_t code;
	uint16_t length;
	uint8_t data[0];
};

#pragma pack(pop)

    struct qrinfo_t
    {
        std::string name_;
        uint16_t type_ = 0;
        uint16_t class_ = 0;
    };

    struct rrinfo_t : public qrinfo_t
    {
        uint32_t ttl_ = 0;
        std::string data_;
    };

    class Message
    {
    protected:
        //Head
        head_t head_ = {0};
        //Queries
        std::vector<qrinfo_t> qrs_;
        //RRs
        std::vector<rrinfo_t> rrs_[rr_type_t::MAX];
        //data
        std::string data_;
    public:
        Message()
        {
            data_.reserve(DNS_DEF_DATA_SIZE);
        }

        int Parse(const char* lpBuf, int & nBufLen) {
            if (nBufLen < sizeof(head_t)) {
                return SOCKET_PACKET_FLAG_PENDING;
            }
            int ret = 0;
            XRBuffer buff(lpBuf,nBufLen,true);
            head_.id = buff.readInt16();
            head_.flags = buff.readInt16();
            head_.Questions = buff.readInt16();
            head_.AnswerRRs = buff.readInt16();
            head_.AuthorityRRs = buff.readInt16();
            head_.AdditionalRRs = buff.readInt16();
            qrs_.clear();
            for (int i = 0; i < head_.Questions; i++) {
                qrinfo_t info;
                ret = readQR(buff,info);
                if (ret < 0) {
                    PRINTF("decode Questions failed.");
                    return -1;
                }
                qrs_.emplace_back(info);
            }
            rrs_[rr_type_t::AN].clear();
            for (int i = 0; i < head_.AnswerRRs; i++) {
                rrinfo_t info;
                ret = readRR(buff,info);
                if (ret < 0) {
                    PRINTF("decode AnswerRRs failed.");
                    return -1;
                }
                rrs_[rr_type_t::AN].emplace_back(info);
            }
            rrs_[rr_type_t::NS].clear();
            for (int i = 0; i < head_.AuthorityRRs; i++) {
                rrinfo_t info;
                ret = readRR(buff,info);
                if (ret < 0) {
                    PRINTF("decode AuthorityRRs failed.");
                    return -1;
                }
                rrs_[rr_type_t::NS].emplace_back(info);
            }
            rrs_[rr_type_t::AD].clear();
            for (int i = 0; i < head_.AdditionalRRs; i++) {
                rrinfo_t info;
                ret = readRR(buff,info);
                if (ret < 0) {
                    PRINTF("decode AdditionalRRs failed.");
                    return -1;
                }
                rrs_[rr_type_t::AD].emplace_back(info);
            }
            return SOCKET_PACKET_FLAG_COMPLETE; 
        }

        int Encode(char* lpBuf, int & nBufLen) {
            XBuffer buff(DNS_DEF_DATA_SIZE);
            if(buff.writable() < sizeof(head_t)) {
                return SOCKET_PACKET_FLAG_PENDING;
            }
            buff.writeInt16(head_.id);
            buff.writeInt16(head_.flags);
            buff.writeInt16(head_.Questions);
            buff.writeInt16(head_.AnswerRRs);
            buff.writeInt16(head_.AuthorityRRs);
            buff.writeInt16(head_.AdditionalRRs);
            return SOCKET_PACKET_FLAG_COMPLETE; 
        }
    
    protected:
        //
        inline int readDomain(XRBuffer &buff, char *output, int size)
        {
            int output_len = 0;
            int copy_len = 0;
            int len = 0;
            unsigned char *begin = buff.begin(), *ptr = buff.reader(), *end = buff.end();
            int is_compressed = 0;
            int ptr_jump = 0;

            /*[len]string[len]string...[0]0 */
            while (1) {
                if (ptr > end || ptr < begin || output_len >= size - 1 || ptr_jump > 4) {
                    return -1;
                }

                len = *ptr;
                if (len == 0) {
                    *output = 0;
                    ptr++;
                    break;
                }

                /* compressed domain */
                if (len >= 0xC0) {
                    if ((ptr + 2) > end) {
                        return -1;
                    }
                    /*
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    | 1  1|                OFFSET                   |
                    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    */
                    /* read offset */
                    int offset = buff.readInt16() & 0x3FFF;
                    if (is_compressed == 0) {
                        buff.retrieve(ptr-buff.reader());
                    }
                    ptr = begin() + offset;
                    if (ptr > end) {
                        PRINTF("length is not enough");
                        return -1;
                    }
                    is_compressed = 1;
                    ptr_jump++;
                    continue;
                }

                ptr_jump = 0;

                /* change [len] to '.' */
                if (output_len > 0) {
                    *output = '.';
                    output++;
                    output_len += 1;
                }

                if (ptr > end) {
                    PRINTF("length is not enough");
                    return -1;
                }

                ptr++;
                if (output_len < size - 1) {
                    /* copy sub string */
                    copy_len = (len < size - output_len) ? len : size - 1 - output_len;
                    if ((ptr + copy_len) > end) {
                        PRINTF("length is not enough");
                        return -1;
                    }
                    memcpy(output, ptr, copy_len);
                }

                ptr += len;
                output += len;
                output_len += len;
            }

            if (is_compressed == 0) {
                buff.retrieve(ptr-buff.reader());
            }

            return output_len;
        }
        inline int readDomain(XRBuffer &buff, std::string &str)
        {
            char cname[DNS_MAX_CNAME_LEN] = {0};
            int len = readDomain(buff, cname, DNS_MAX_CNAME_LEN);
            if(len >= 0) {
                str = cname;
            }
            return len;
        }
        
        inline int readOpt((XRBuffer &buff, rrinfo_t& out, int rr_len)
        {
            uint16_t opt_code;
            uint16_t opt_len;
            uint16_t ercode = (out.ttl_ >> 16) & 0xFFFF;
            unsigned char *start = buff.reader();
            struct dns_packet *packet = context->packet;
            int ret = 0;

            /*
                Field Name   Field Type     Description
            ------------------------------------------------------
            NAME         domain name    empty (root domain)
            TYPE         u_int16_t      OPT
            CLASS        u_int16_t      sender's UDP payload size
            TTL          u_int32_t      extended RCODE and flags
            RDLEN        u_int16_t      describes RDATA
            RDATA        octet stream   {attribute,value} pairs

                            +0 (MSB)                            +1 (LSB)
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        0: |                          OPTION-CODE                          |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        2: |                         OPTION-LENGTH                         |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        4: |                                                               |
            /                          OPTION-DATA                          /
            /                                                               /
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

            TTL
                        +0 (MSB)                            +1 (LSB)
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        0: |         EXTENDED-RCODE        |            VERSION            |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        2: |                               Z                               |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
            */

            if (ercode != 0) {
                PRINTF("extend rcode invalid.");
                return -1;
            }

            while (buff.reader() - start < rr_len) {
                if (buff.readable() < 4) {
                    return -1;
                }
                opt_code = buff.readInt16();
                opt_len = buff.readInt16();

                if (buff.readable() < opt_len) {
                    PRINTF("read opt data failed, opt_code = %d, opt_le = %d", opt_code, opt_len);
                    return -1;
                }

                switch (opt_code) {
                case opt_code_t::ECS: {
                    opt_ecs_t ecs;
                    int len = 0;
                    if (buff.readable() < 4) {
                        return -1;
                    }

                    ecs->family = buff.readInt16();
                    ecs->source_prefix = buff.readInt8();
                    ecs->scope_prefix = buff.readInt8();
                    len = (ecs->source_prefix / 8);
                    len += (ecs->source_prefix % 8 > 0) ? 1 : 0;

                    if (buff.readable() < len) {
                        return -1;
                    }

                    buff.read(ecs->addr, len);

                    PRINTF("ECS: family:%d, source_prefix:%d, scope_prefix:%d, len:%d", ecs->family, ecs->source_prefix, ecs->scope_prefix, len);
                    PRINTF("%d.%d.%d.%d", ecs->addr[0], ecs->addr[1], ecs->addr[2], ecs->addr[3]);

                    size_t old_len = out.data_.size();
                    out.data_.resize(old_len+sizeof(ecs));
                    memcpy(&out.data_[old_len], &ecs, sizeof(ecs));
                } break;
                default: {
                    buff.retirve(opt_len);
                    PRINTF("DNS opt type = %d not supported", opt_code);
                } break;
                }
            }

            return 0;
        }


        inline int readQR(XRBuffer &buff, qrinfo_t &out)
        {
            int ret = 0;
            /*
            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                                               |
            /                                               /
            /                      NAME                     /
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TYPE                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     CLASS                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            */
            ret = readDomain(buff, out.name_);
            if (ret < 0) {
                PRINTF("readDomain failed.");
                return -1;
            }

            if (buff.readable() < 4) {
                PRINTF("left length is not enough, %s.", out.name_.c_str());
                return -1;
            }

            out.type_ = buff.readInt16();
            out.class_ = buff.readInt16();

            return 0;
        }
        
        inline int readRR(XRBuffer &buff, rrinfo_t& out)
        {
            readQR(buff, out);
            size_t left = buff.readable();
            if (left < 0) {
                PRINTF("decode qr head failed.");
                return -1;
            }

            if (left < 4) {
                PRINTF("left length is not enough.");
                return -1;
            }
            out.type_ = buff.readInt32();

            return 0;
        }

        inline int readRR(XRBuffer &buff, rrinfo_t& out, rr_type_t type)
        {
            int ret;
            ret = readRR(buff, out);
            if (ret < 0) {
                return -1;
            }
            if(buff.readable() <  2) {
                 PRINTF("decode data length failed");
                return -1;
            }
            size_t data_len = buff.readInt16();
            if(buff.readable() < data_len) {
                PRINTF("decode data failed");
                return -1;
            }
	        unsigned char *start = buff.reader();
            /* decode answer */
            switch (out.type_) {
            case type_t::A: {
                out.data_.resize(data_len);
                buff.read((char*)out.data_.data(),out.data_.size());
            } break;
            case type_t::CNAME: {
                ret = readDomain(buff, out.data_);
            } break;
            case type_t::SOA: {
                buff.resize(sizeof(soa_t));
                soa_t& soa = *(soa_t*)buff.data();
                ret = readDomain(buff, soa->mname, DNS_MAX_CNAME_LEN-1);
                if (ret < 0) {
                    return -1;
                }

                ret = readDomain(buff, soa->rname, DNS_MAX_CNAME_LEN-1);
                if (ret < 0) {
                    return -1;
                }

                if (buff.readable() < 20) {
                    return -1;
                }

                soa->serial = buff.readInt32();
                soa->refresh = buff.readInt32();
                soa->retry = buff.readInt32();
                soa->expire = buff.readInt32();
                soa->minimum = buff.readInt32();
            } break;
            case type_t::NS: {
                ret = readDomain(buff, out.data_);
            } break;
            case type_t::PTR: {
                ret = readDomain(buff, out.data_);
            } break;
            case type_t::AAAA: {
                out.data_.resize(data_len);
                buff.read((char*)out.data_.data(),out.data_.size());
            } break;
            case type_t::OPT: {
                unsigned char *opt_start = buff.reader();
                ret = readOpt(buff, out, data_len);
                if (ret < 0) {
                    PRINTF("decode opt failed");
                    return -1;
                }

                if (buff.reader() - opt_start != data_len) {
                    PRINTF("opt length mismatch");
                    return -1;
                }

                /*uint16_t payload_size = out.class_;
                if (payload_size < 512) {
                    payload_size = 512;
                }
                data_.resize(payload_size);*/
            } break;
            default: {
                out.data_.resize(data_len);
                buff.read((char*)out.data_.data(),out.data_.size());
            } break;
            }

            if (buff.reader() - start != data_len) {
                PRINTF("length mismatch");
                return -1;
            }

            return 0;
        }
    };
}
    template<class TBase>
    class DNSSocketT : public TBase
    {
        typedef TBase Base;
    public:

    protected:
        //
        virtual void OnDNSMessage(DNS::Message& msg)
        {

        }
    };
}

#endif//_H_XDNS_IMPL_H_