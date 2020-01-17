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

enum qr_t 
{
	QR_QUERY = 0,
	QR_RESPONSE = 1,
};

const uint16_t QR_MASK = 0x8000;
const uint16_t OPCODE_MASK = 0x7800;
const uint16_t AA_MASK = 0x0400;
const uint16_t TC_MASK = 0x0200;
const uint16_t RD_MASK = 0x0100;
const uint16_t RA_MASK = 0x0080;
const uint16_t RCODE_MASK = 0x000F;

enum opcode_t 
{
	OPCODE_QUERY = 0,
	OPCODE_IQUERY = 1,
	OPCODE_STATUS = 2,
	OPCODE_NOTIFY = 4,
	OPCODE_UPDATE = 5,
};

enum rcode_t {
    RCODE_NOERROR = 0,
	RCODE_FORMERR = 1,
	RCODE_SERVFAIL = 2,
	RCODE_NXDOMAIN = 3,
	RCODE_NOTIMP = 4,
	RCODE_REFUSED = 5,
	RCODE_YXDOMAIN = 6,
	RCODE_YXRRSET = 7,
	RCODE_NXRRSET = 8,
	RCODE_NOTAUTH = 9,
	RCODE_NOTZONE = 10,
};
    /*
    +high---------------low+high-----------------low+
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
    // union {
    //     uint16_t flags;
    //     struct
    //     {
            uint16_t QR : 1;     //0:query 1:response
            uint16_t opcode : 4; //
            uint16_t AA : 1;     //1:Authoritative Answer
            uint16_t TC : 1;     //1:Truncation
            uint16_t RD : 1;     //1:Recursion Desired
            uint16_t RA : 1;     //1:Recursion Available
            uint16_t zero : 3;   //
            uint16_t rcode : 4;  //Response Code
    //     };
    // };
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

// 常见资源记录说明：
// A 记录:
// 描述：主机地址(A) 资源记录。将 DNS 域名映射到 Internet 协议(IP) 版本 4 的 32 位地址中（RFC 1035）
// AAAA 记录:
// 描述：IPv6 主机地址 (AAAA) 资源记录。将 DNS 域名映射到 Internet 协议 (IP) 版本 6 的 128 位地址中（RFC 1886）
// NS 记录：
// 描述：将 owner 中指定的 DNS 域名映射到在 name_server_domain_name 字段中指定的运行 DNS 服务器的主机名
// NXT 记录：
// 描述：下一资源记录。NXT 资源记录通过在域中创建所有字面上的所有者名称链，指出某个名称在域中不存在。它们同时也指出，一个已有名称当前有什么资源记录类型。
// MR记录：
// 描述：邮箱重命名 (MR) 资源记录。在 new_renamed_mailbox 中指定域邮箱名，作为对 owner 字段中指定的现有邮箱的合适重命名。MR 资源记录经常用做已移至不同邮箱的用户的转发项目。
// MR 记录不产生额外的节处理。
// MINFO 记录：
// 描述：邮箱邮件列表信息 (MINFO) 资源记录。为维护 owner 字段中指定的邮寄列表或邮箱的负责人指定（在 responsible_mailbox 中）域邮箱名。
// error_mailbox 字段也可用于指定接收与该邮寄列表或邮箱相关的错误消息的域邮箱。为负责联系人和错误转发指定的邮箱必须与当前区域中已存在的有效邮箱 (MB) 记录相同。
// KEY 记录：
// 描述：公钥资源记录。包含与区域有关的公钥。在完整的 DNSSEC 实现中，解析程序和服务器使用 KEY 资源记录来验证从签名区域接收的 SIG 资源记录。
// KEY 资源记录由父区域来签名，使知道父区域的公钥的服务器可以发现和验证子区域的密钥。从签名区域接收资源记录的名称服务器或解析程序获取相应的 SIG 记录，然后检索该区域的 KEY 记录。
// HINFO 记录：
// 描述：主机信息 (HINFO) 资源记录。针对 owner 字段中的主机 DNS 域名分别在 cpu_type 和 os_type 字段中指定 CPU 和操作系统的类型。大家都知道的最常用 CPU 和操作系统类型记录在 RFC 1700 中。 该信息可由 FTP 这样的应用协议使用，这些协议在与已知 CPU 和操作系统类型的计算机通讯时使用特殊的过程。
// CNAME 记录：
// 描述：规范名 (CNAME) 资源记录。将 owner 字段中的别名或备用的 DNS 域名映射到 canonical_name 字段中指定的标准或主要 DNS 域名。
// 此数据中所使用的标准或主要 DNS 域名是必需的，并且必须解析为名称空间中有效的 DNS 域名
// SOA 记录： 
// 描述：起始授权机构 (SOA) 资源记录。指示区域的源名称，并包含作为区域主要信息源的服务器的名称。它还表示该区域的其他基本属性。
// SOA 资源记录在任何标准区域中始终是首位记录。它表示最初创建它的 DNS 服务器或现在是该区域的主服务器的 DNS 服务器。
// 它还用于存储会影响区域更新或过期的其他属性，如版本信息和计时。这些属性会影响在该区域的权威服务器之间进行区域传输的频繁程度语法：
// owner TTL CLASS SOA name_server responsible_person(serial_number refresh_interval retry_interval expiration minimum_time_to_live)
// PTR 记录：
// 描述：指针 (PTR) 资源记录。正如 targeted_domain_name 中所指定的那样，从 owner 中的名称指向 DNS 名称空间中的另一位置。经常在诸如 in-addr.arpa 域树的特殊域中使用，
// 以提供地址-名称映射的反向查找。在大多数情况下，每个记录提供指向另一 DNS 域名位置的信息，如正向查找区域中的相应主机 (A) 地址资源记录（RFC 1035）
// MX 记录：
// 描述：邮件交换器 (MX) 资源记录如 mail_exchanger_host 中指定的那样，为邮件交换器主机提供邮件路由，以便将邮件发送给 owner 字段中指定的域名。
// preference 表示在指定了多个交换器主机情况下的首选顺序。每个交换机主机都必须在有效区域中有一个相应的主机 (A) 地址资源记录（RFC 1035）
// TXT 记录：
// 描述：文本 (TXT) 资源记录。将 owner 字段中指定的 DNS 域名映射到充作说明文本的 text_string 中的字符串。
// OPT 记录：
// 描述：选项资源记录。可将一个 OPT 资源记录添加到 DNS 请求或响应的附加数据部分。OPT 资源记录属于特定传输层消息（例如，UDP），不属于实际 DNS 数据。
// 每条消息只允许具有一个 OPT 资源记录，但不是必需选项。
enum type_t {
	TYPE_A = 1,
	TYPE_NS = 2,
	TYPE_CNAME = 5,
	TYPE_SOA = 6,
	TYPE_PTR = 12,
	TYPE_MX = 15,
	TYPE_TXT = 16,
	TYPE_AAAA = 28,
	TYPE_SRV = 33,
	TYPE_OPT = 41,
	TYPE_SSHFP = 44,
	TYPE_SPF = 99,
	TYPE_AXFR = 252,
	TYPE_ALL = 255
};

const size_t RR_A_LEN = 4;
const size_t RR_AAAA_LEN = 16;

enum class_t {
    CLASS_IN = 1,
    CLASS_ANY = 255 
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
	OPT_CODE_ECS = 8, 
	OPT_CODE_TCP_KEEPALIVE = 11,
	OPT_CODE_ALL = 255 
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
        enum  
        {
            RR_AN = 0,
            RR_NS = 1,
            RR_AD = 2,
            RR_OPT = 3,
            RR_MAX = 4,
        };
        std::vector<rrinfo_t> rrs_[RR_MAX];
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
            //head_.flags = buff.readInt16();
            uint16_t flags = buff.readInt16();
            head_.QR = (flags & QR_MASK) >> 15;
            head_.opcode = (flags & OPCODE_MASK) >> 11;
            head_.AA = (flags & AA_MASK) >> 10;
            head_.TC = (flags & TC_MASK) >> 9;
            head_.RD = (flags & RD_MASK) >> 8;
            head_.RA = (flags & RA_MASK) >> 7;
            head_.rcode = (flags & RCODE_MASK) >> 0;
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
            rrs_[RR_AN].clear();
            for (int i = 0; i < head_.AnswerRRs; i++) {
                rrinfo_t info;
                ret = readRR(buff,info);
                if (ret < 0) {
                    PRINTF("decode AnswerRRs failed.");
                    return -1;
                }
                rrs_[RR_AN].emplace_back(info);
            }
            rrs_[RR_NS].clear();
            for (int i = 0; i < head_.AuthorityRRs; i++) {
                rrinfo_t info;
                ret = readRR(buff,info);
                if (ret < 0) {
                    PRINTF("decode AuthorityRRs failed.");
                    return -1;
                }
                rrs_[RR_NS].emplace_back(info);
            }
            rrs_[RR_AD].clear();
            for (int i = 0; i < head_.AdditionalRRs; i++) {
                rrinfo_t info;
                ret = readRR(buff,info);
                if (ret < 0) {
                    PRINTF("decode AdditionalRRs failed.");
                    return -1;
                }
                rrs_[RR_AD].emplace_back(info);
            }
            return SOCKET_PACKET_FLAG_COMPLETE; 
        }

        int Encode(XBuffer& buff) {
            int ret = 0;
            buff.writeInt16(head_.id);
            uint16_t flags = 0;
            flags |= (head_.QR << 15) & QR_MASK;
            flags |= (head_.opcode << 11) & OPCODE_MASK;
            flags |= (head_.AA << 10) & AA_MASK;
            flags |= (head_.TC << 9) & TC_MASK;
            flags |= (head_.RD << 8) & RD_MASK;
            flags |= (head_.RA << 7) & RA_MASK;
            flags |= (head_.rcode << 0) & RCODE_MASK;
            buff.writeInt16(flags);
            //buff.writeInt16(head_.flags);
            buff.writeInt16(head_.Questions);
            buff.writeInt16(head_.AnswerRRs);
            buff.writeInt16(head_.AuthorityRRs);
            buff.writeInt16(head_.AdditionalRRs);
            for (int i = 0; i < head_.Questions; i++) {
                const qrinfo_t& info = qrs_[i];
                ret = writeQR(buff,info);
                if (ret < 0) {
                    PRINTF("encode Questions failed.");
                    return -1;
                }
            }
            for (int i = 0; i < head_.AnswerRRs; i++) {
                const rrinfo_t& info = rrs_[RR_AN][i];
                ret = writeRR(buff,info);
                if (ret < 0) {
                    PRINTF("encode AnswerRRs failed.");
                    return -1;
                }
            }
            for (int i = 0; i < head_.AuthorityRRs; i++) {
                const rrinfo_t& info = rrs_[RR_NS][i];
                ret = writeRR(buff,info);
                if (ret < 0) {
                    PRINTF("encode AuthorityRRs failed.");
                    return -1;
                }
            }
            for (int i = 0; i < head_.AdditionalRRs; i++) {
                const rrinfo_t& info = rrs_[RR_AD][i];
                ret = writeRR(buff,info);
                if (ret < 0) {
                    PRINTF("encode AdditionalRRs failed.");
                    return -1;
                }
            }
            return SOCKET_PACKET_FLAG_COMPLETE;
        }

        head_t& Head() { return head_; }
        inline std::vector<qrinfo_t>& QRs() { return qrs_; };
        inline std::vector<rrinfo_t>& AnswerRRs() { return rrs_[RR_AN]; }
        inline std::vector<rrinfo_t>& AuthorityRRs() { return rrs_[RR_NS]; }
        inline std::vector<rrinfo_t>& AdditionalRRs() { return rrs_[RR_AD]; }
        inline std::string& Payload() { return data_; }
    
    protected:
        //
        inline int readDomain(XRBuffer &buff, char *output, int size)
        {
            int output_len = 0;
            int copy_len = 0;
            int len = 0;
            uint8_t *ptr = (uint8_t*)buff.reader();
            int is_compressed = 0;
            int ptr_jump = 0;

            /*[len]string[len]string...[0]0 */
            while (1) {
                if (!buff.readable() || ptr_jump > 4) {
                    return -1;
                }

                len = buff.readInt8();
                if (len == 0) {
                    *output = 0;
                    break;
                }

                /* compressed domain */
                if (len >= 0xC0) {
                    buff.unread(1);
                    if (buff.readable() < 2) {
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
                        ptr = (uint8_t*)buff.reader();
                    }
                    buff.reset(offset);
                    if (!buff.readable()) {
                        PRINTF("length is not enough");
                        return -1;
                    }
                    is_compressed = 1;
                    ptr_jump++;
                    continue;
                }

                ptr_jump = 0;

                /* change [len] to '.' */
                if (output_len > 0 && output_len < size - 1) {
                    *output = '.';
                    output++;
                    output_len += 1;
                }

                if (buff.readable() < len) {
                    PRINTF("length is not enough");
                    return -1;
                }

                if (output_len < size - 1) {
                    /* copy sub string */
                    copy_len = (len < size - output_len) ? len : size - 1 - output_len;
                    if (copy_len > buff.readable()) {
                        PRINTF("length is not enough");
                        return -1;
                    }
                    buff.read(output, copy_len);
                } else {
                    buff.retrieve(len);
                }

                output += len;
                output_len += len;
            }
            
            if (is_compressed == 1) {
                buff.reset(ptr-(uint8_t*)buff.begin());
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
        inline int writeDomain(XBuffer &buff, const char *str, int len)
        {
            const char* cname = str;
            int cnum = 0;
            /*[len]string[len]string...[0]0 */
            for(int i = 0; i < len; i++)
            {
                if (str[i] == '.') {
                    buff.writeInt8(cnum);
                    buff.write(cname,cnum);
                    if((i+1) < len) {
                        cname = &str[i+1];
                        cnum = 0;
                        continue;
                    } else {
                        cname = nullptr;
                        cnum = 0;
                        break;
                    }
                } else {
                    cnum++;
                }
            }
            buff.writeInt8(cnum);
            if(cname) {
                buff.write(cname,cnum);
                buff.writeInt8(0);
            }
            return 0;
        }
        inline int writeDomain(XBuffer &buff, const std::string &str)
        {
            return writeDomain(buff, str.c_str(), str.size());
        }
        
        inline int readOpt(XRBuffer &buff, rrinfo_t& out, int rr_len)
        {
            /*
            Field Name   Field Type     Description
            ------------------------------------------------------
            NAME         domain name    empty (root domain)
            TYPE         u_int16_t      OPT
            CLASS        u_int16_t      sender's UDP payload size
            TTL          u_int32_t      extended RCODE and flags
            RDLEN        u_int16_t      describes RDATA
            RDATA        octet stream   {attribute,value} pairs

            TTL
                        +0 (MSB)                            +1 (LSB)
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        0: |         EXTENDED-RCODE        |            VERSION            |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
        2: |                               Z                               |
            +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

            OPT(RDLEN+RDDATA)
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
            */

            int ret = 0;
            uint16_t opt_code;
            uint16_t opt_len;
            uint16_t ercode = (out.ttl_ >> 16) & 0xFFFF;
            uint8_t *start = (uint8_t*)buff.reader();

            if (ercode != 0) {
                PRINTF("extend rcode invalid.");
                return -1;
            }

            while ((uint8_t*)buff.reader() - start < rr_len) {
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
                case OPT_CODE_ECS: {
                    opt_ecs_t ecs;
                    int len = 0;
                    if (buff.readable() < 4) {
                        return -1;
                    }

                    ecs.family = buff.readInt16();
                    ecs.source_prefix = buff.readInt8();
                    ecs.scope_prefix = buff.readInt8();
                    len = (ecs.source_prefix / 8);
                    len += (ecs.source_prefix % 8 > 0) ? 1 : 0;

                    if (buff.readable() < len) {
                        return -1;
                    }

                    buff.read((char*)ecs.addr, len);

                    PRINTF("ECS: family:%d, source_prefix:%d, scope_prefix:%d, len:%d", ecs.family, ecs.source_prefix, ecs.scope_prefix, len);
                    PRINTF("%d.%d.%d.%d", ecs.addr[0], ecs.addr[1], ecs.addr[2], ecs.addr[3]);

                    size_t old_len = out.data_.size();
                    out.data_.resize(old_len+sizeof(ecs));
                    memcpy(&out.data_[old_len], &ecs, sizeof(ecs));
                } break;
                default: {
                    buff.retrieve(opt_len);
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
        inline int writeQR(XBuffer &buff, const qrinfo_t &in)
        {
            int ret = 0;
            ret = writeDomain(buff, in.name_);
            if (ret < 0) {
                return -1;
            }

            buff.writeInt16(in.type_);
            buff.writeInt16(in.class_);

            return 0;
        }
        
        inline int readRRHead(XRBuffer &buff, rrinfo_t& out)
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
            out.ttl_ = buff.readInt32();

            return 0;
        }
        inline int writeRRHead(XBuffer &buff, const rrinfo_t& in)
        {
            writeQR(buff, in);

            buff.writeInt32(in.ttl_);

            return 0;
        }

        inline int readRR(XRBuffer &buff, rrinfo_t& out)
        {
            int ret;
            ret = readRRHead(buff, out);
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
	        uint8_t *start = (uint8_t*)buff.reader();
            /* decode answer */
            switch (out.type_) {
            case TYPE_A: {
                out.data_.resize(data_len);
                buff.read((char*)out.data_.data(),out.data_.size());
            } break;
            case TYPE_CNAME: {
                ret = readDomain(buff, out.data_);
            } break;
            case TYPE_SOA: {
                out.data_.resize(sizeof(soa_t));
                soa_t& soa = *(soa_t*)out.data_.data();
                ret = readDomain(buff, soa.mname, DNS_MAX_CNAME_LEN-1);
                if (ret < 0) {
                    return -1;
                }

                ret = readDomain(buff, soa.rname, DNS_MAX_CNAME_LEN-1);
                if (ret < 0) {
                    return -1;
                }

                if (buff.readable() < 20) {
                    return -1;
                }

                soa.serial = buff.readInt32();
                soa.refresh = buff.readInt32();
                soa.retry = buff.readInt32();
                soa.expire = buff.readInt32();
                soa.minimum = buff.readInt32();
            } break;
            case TYPE_NS: {
                ret = readDomain(buff, out.data_);
            } break;
            case TYPE_PTR: {
                ret = readDomain(buff, out.data_);
            } break;
            case TYPE_AAAA: {
                out.data_.resize(data_len);
                buff.read((char*)out.data_.data(),out.data_.size());
            } break;
            case TYPE_OPT: {
                uint8_t *opt_start = (uint8_t*)buff.reader();
                ret = readOpt(buff, out, data_len);
                if (ret < 0) {
                    PRINTF("decode opt failed");
                    return -1;
                }

                if ((uint8_t*)buff.reader() - opt_start != data_len) {
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

            if ((uint8_t*)buff.reader() - start != data_len) {
                PRINTF("length mismatch");
                return -1;
            }

            return 0;
        }
        inline int writeRR(XBuffer &buff, const rrinfo_t& in)
        {
            int ret;
            ret = writeRRHead(buff, in);
            if (ret < 0) {
                return -1;
            }
            switch (in.type_) {
            case TYPE_A:
            case TYPE_AAAA: {
                buff.writeInt16(in.data_.size());
                buff.write(in.data_.data(), in.data_.size());
            } break;
            case TYPE_CNAME:
            case TYPE_PTR: {
                ret = writeDomain(buff, in.name_);
                if (ret < 0) {  
                    return -1;
                }
            } break;
            case TYPE_SOA: {
                soa_t& soa = *(soa_t*)in.data_.data();
                ret = writeDomain(buff, soa.mname, strlen(soa.mname));
                if (ret < 0) {
                    return -1;
                }
                ret = writeDomain(buff, soa.rname, strlen(soa.rname));
                if (ret < 0) {
                    return -1;
                }
                buff.writeInt32(soa.serial);
                buff.writeInt32(soa.refresh);
                buff.writeInt32(soa.retry);
                buff.writeInt32(soa.expire);
                buff.writeInt32(soa.minimum);
            } break;
            default:
            break;
            }
            return 0;
        }
    };
}

template<class TBase>
class DNSSocketBaseT : public TBase
{
    typedef TBase Base;
public:

protected:
	//
	//解析数据包
	int Parse(const char* lpBuf, int & nBufLen) { 
		int nParseFlags = 0;
		DNS::Message msg;
        nParseFlags = msg.Parse(lpBuf, nBufLen);
        if(nParseFlags & SOCKET_PACKET_FLAG_COMPLETE) {
            OnDNSMessage(msg);
        }
		return nParseFlags;
	}

    virtual void OnDNSMessage(DNS::Message& msg)
    {

    }
};

template<class TBase>
class DNSSocketT : public DNSSocketBaseT<TBase>
{
    typedef DNSSocketBaseT<TBase> Base;
public:

protected:
	//
	//解析数据包
	int ParseBuf(const char* lpBuf, int & nBufLen) { 
		return Parse(lpBuf,nBufLen);
	}

};

template<class TBase>
class DNSUdpSocketT : public DNSSocketBaseT<TBase>
{
    typedef DNSSocketBaseT<TBase> Base;
public:
	typedef typename Base::SockAddr SockAddr;
    
protected:
	//
	//解析数据包
    int ParseBuf(const char* lpBuf, int & nBufLen, const SockAddr & stAddr)
    {
        return Parse(lpBuf,nBufLen);
    }
};

template<class TBase>
class DNSClientSocketT : public TBase
{
    typedef TBase Base;
public:

protected:
	//
    void OnDNSMessage(DNS::Message& msg)
    {
        /* not answer, return error */
        if (msg.Head().QR != DNS::QR_RESPONSE) {
            PRINTF("message type error.");
            return;
        }
    }
};

}

#endif//_H_XDNS_IMPL_H_