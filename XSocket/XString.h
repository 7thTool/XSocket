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
#ifndef _H_XSOCKET_STRING_H_
#define _H_XSOCKET_STRING_H_

#include "XSocketDef.h"
#include "XMemory.h"

namespace XSocket {

	typedef std::basic_string<char, std::char_traits<char>, AllocatorT<char>> String;
	typedef std::basic_istringstream<char, std::char_traits<char>, AllocatorT<char>> IStringStream;
	typedef std::basic_ostringstream<char, std::char_traits<char>, AllocatorT<char>> OStringStream;
	typedef std::basic_stringstream<char, std::char_traits<char>, AllocatorT<char>> StringStream;

	template<typename Target>
	inline Target strto(const String& arg, const Target& def = Target())
	{
		if (!arg.empty()) {
			try
			{
				Target o;
				StringStream ss;
				ss << arg;
				ss >> o;
				return o;
			}
			catch(std::exception& e)
			{

			}
			catch (...)
			{

			}
		}
		return def;
	}

	template<typename Source>
	inline String tostr(const Source& arg)
	{
		OStringStream ss;
		ss << arg;
		return ss.str();
	}

	template<typename Source>
	inline String tostrex(const Source& arg, int p = -1, int w = -1, char c = '0')
	{
		OStringStream ss;
		if (p>=0) {
			ss.setf(std::ios::fixed);
			ss.precision(p);
		}
		if (w>=0) {
			ss.width(w);
			ss.fill(c);
		}
		ss << arg;
		return ss.str();
	}
}

#endif//_H_XSOCKET_STRING_H_