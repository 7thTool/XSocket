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

enum class_t 
{
    DNS_C_IN = 1,
    DNS_C_ANY = 255 
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

// struct SOA {
// 	char mname[DNS_MAX_CNAME_LEN];
// 	char rname[DNS_MAX_CNAME_LEN];
// 	unsigned int serial;
// 	unsigned int refresh;
// 	unsigned int retry;
// 	unsigned int expire;
// 	unsigned int minimum;
// };

enum opt_code_t
{ 
	ECS = 8, 
	TCP_KEEPALIVE = 11,
	ALL = 255 
};

struct opt {
	uint16_t code;
	uint16_t length;
	uint8_t data[0];
};

#pragma pack(pop)

    struct qrinfo_t
    {
        std::vector<std::string> name_;
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
        //payload data
        std::string payload_;
    public:
        int Parse(const char* lpBuf, int & nBufLen) {
            if (nBufLen < sizeof(head_t)) {
                return SOCKET_PACKET_FLAG_PENDING;
            }
            XRBuffer buff(lpBuf,nBufLen,true);
            head_.id = buff.readInt16(false);
            head_.flags = buff.readInt16(false);
            head_.Questions = buff.readInt16(false);
            head_.AnswerRRs = buff.readInt16(false);
            head_.AuthorityRRs = buff.readInt16(false);
            head_.AdditionalRRs = buff.readInt16(false);
            return SOCKET_PACKET_FLAG_COMPLETE; 
        }
    
    protected:
        inline bool readDomain(XRBuffer &buff, std::string &str)
        {
            while(buff.readable())
            {
                size_t len = buff.readInt8(false);
                if (len == 0)
                {
                    break;
                }
                if (len >= 0xC0)
                {
                    if (buff.readable() < 2)
                    {
                        return false;
                    }
                    /*
                    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    | 1  1|                LENGTH                   |
                    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    */
                    len = buff.readInt16() & 0x3FFF;
                }
                if (readable() < len)
                {
                    return false;
                }
                size_t old_size = str.size();
                if (!old_size)
                {
                    str.resize(len);
                }
                else
                {
                    str.resize(old_size + 1 + len);
                    str[old_size++] = '.';
                }
                buff.read((char *)str.data() + old_size, len);
            }
            return true;
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