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
#ifndef _H_XSTR_H_
#define _H_XSTR_H_

#include "XSocketDef.h"

namespace XSocket {

#ifndef strupr
inline char *_strupr(char *s)
{
	char *str;
	str = s;
	while(*str != '\0')
	{
		if(*str >= 'a' && *str <= 'z') {
			*str += 'A'-'a';
		}
		str++;
	}
	return s;
}
#define strupr _strupr
#endif//strupr

#ifndef strlwr
inline char *_strlwr(char *s)
{
	char *str;
	str = s;
	while(*str != '\0')
	{
		if(*str >= 'A' && *str <= 'Z') {
			*str += 'a'-'A';
		}
		str++;
	}
	return s;
}
#define strlwr _strlwr
#endif//strlwr

inline char chupr(char ch) {
    if(ch >= 'a' && ch <= 'z') {
        ch -= 32; 
    }
    return ch;
}

inline char chlwr(char ch) {
    if(ch >= 'A' && ch <= 'Z') {
        ch += 32;
    }
    return ch;
}

//////////////////////////////////////////////////////////////////////////
///注意：反向处理的的源指针要指向最后，正向处理源指向开始位置，原则就是执行最先开始处理的位置

#ifdef WIN32
#else
inline int memicmp(const char * src, const char * dst, size_t len)
{
	if (src == NULL || dst == NULL || len == 0) {
		return 0;
	}
	else {
		int f = 0, l = 0;
		while (len--)
		{
			f = chupr(*src++);
			l = chupr(*dst++);
			if (f != l) {
				break;
			}
		}
		return (f - l);
	}
}
#endif//
inline int wmemicmp(const wchar_t * src, const wchar_t * dst, size_t len)
{
	if (src == NULL || dst == NULL || len == 0) {
		return 0;
	}
	else {
		int f = 0, l = 0;
		while (len--)
		{
			f = chupr(*src++);
			l = chupr(*dst++);
			if (f != l) {
				break;
			}
		}
		return (f - l);
	}
}

inline int memrcmp(const char * src, const char * dst, size_t rlen)
{
	if (src == NULL || dst == NULL || rlen == 0) {
		return 0;
	}
	else {
		int f = 0, l = 0;
		while (rlen--)
		{
			f = *src--;
			l = *dst--;
			if (f != l) {
				break;
			}
		}
		return (f - l);
	}
}

inline int wmemrcmp(const wchar_t * src, const wchar_t * dst, size_t rlen)
{
	if (src == NULL || dst == NULL || rlen == 0) {
		return 0;
	}
	else {
		int f = 0, l = 0;
		while (rlen--)
		{
			f = *src--;
			l = *dst--;
			if (f != l) {
				break;
			}
		}
		return (f - l);
	}
}

inline int memricmp(const char * src, const char * dst, size_t rlen)
{
	if (src == NULL || dst == NULL || rlen == 0) {
		return 0;
	}
	else {
		int f = 0, l = 0;
		while (rlen--)
		{
			f = chupr(*src--);
			l = chupr(*dst--);
			if (f != l) {
				break;
			}
		}
		return (f - l);
	}
}

inline int wmemricmp(const wchar_t * src, const wchar_t * dst, size_t rlen)
{
	if (src == NULL || dst == NULL || rlen == 0) {
		return 0;
	}
	else {
		int f = 0, l = 0;
		while (rlen--)
		{
			f = chupr(*src--);
			l = chupr(*dst--);
			if (f != l) {
				break;
			}
		}
		return (f - l);
	}
}

inline int strrcmp(const char * src, const char * dst) { return memrcmp(src,dst,strlen(dst)); }
inline int strrnicmp(const char * src, const char * dst, size_t len) { return memricmp(src,dst,len); }
inline int wcsrcmp(const wchar_t * src, const wchar_t * dst) { return wmemrcmp(src,dst,wcslen(dst)); }
inline int wcsrnicmp(const wchar_t * src, const wchar_t * dst, size_t len) { return wmemricmp(src,dst,len); }

inline const char* memmem(const char * src, size_t srclen, const char * dst, size_t dstlen)
{
	if (src == NULL || dst == NULL || srclen < dstlen) {
		return (0);
	}
	else if (srclen == dstlen) {
		return (memcmp(src, dst, dstlen) == 0 ? (char*)src : 0);
	}
	else {
		for (int i = 0, j = srclen - dstlen; i <= j; i++)
		{
			if (memcmp(src + i, dst, dstlen) == 0) {
				return (src + i);
			}
		}
		return (0);
	}
	return 0;
}

inline const wchar_t* wmemmem(const wchar_t * src, size_t srclen, const wchar_t * dst, size_t dstlen)
{
	if (src == NULL || dst == NULL || srclen < dstlen) {
		return (0);
	}
	else if (srclen == dstlen) {
		return (wmemcmp(src, dst, dstlen) == 0 ? (wchar_t*)src : 0);
	}
	else {
		for (int i = 0, j = srclen - dstlen; i <= j; i++)
		{
			if (wmemcmp(src + i, dst, dstlen) == 0) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const char* memimem(const char * src, size_t srclen, const char * dst, size_t dstlen)
{
	if (src == NULL || dst == NULL || srclen < dstlen) {
		return (0);
	}
	else if (srclen == dstlen) {
		return (memicmp(src, dst, dstlen) == 0 ? (char*)src : 0);
	}
	else {
		for (int i = 0, j = srclen - dstlen; i <= j; i++)
		{
			if (memicmp(src + i, dst, dstlen) == 0) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const wchar_t* wmemimem(const wchar_t * src, size_t srclen, const wchar_t * dst, size_t dstlen)
{
	if (src == NULL || dst == NULL || srclen < dstlen) {
		return (0);
	}
	else if (srclen == dstlen) {
		return (wmemicmp(src, dst, dstlen) == 0 ? (wchar_t*)src : 0);
	}
	else {
		for (int i = 0, j = srclen - dstlen; i <= j; i++)
		{
			if (wmemicmp(src + i, dst, dstlen) == 0) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const char* memrmem(const char * src, size_t srcrlen, const char * dst, size_t dstrlen)
{
	if (src == NULL || dst == NULL || srcrlen < dstrlen) {
		return (0);
	}
	else if (srcrlen == dstrlen) {
		return (memrcmp(src, dst, dstrlen) == 0 ? (char*)src : 0);
	}
	else {
		for (int i = 0, j = srcrlen - dstrlen; i <= j; i++)
		{
			if (memrcmp(src - i, dst, dstrlen) == 0) {
				return (src - i);
			}
		}
		return (0);
	}
	return 0;
}

inline const wchar_t* wmemrmem(const wchar_t * src, size_t srcrlen, const wchar_t * dst, size_t dstrlen)
{
	if (src == NULL || dst == NULL || srcrlen < dstrlen) {
		return (0);
	}
	else if (srcrlen == dstrlen) {
		return (wmemrcmp(src, dst, dstrlen) == 0 ? (wchar_t*)src : 0);
	}
	else {
		for (int i = 0, j = srcrlen - dstrlen; i <= j; i++)
		{
			if (wmemrcmp(src - i, dst, dstrlen) == 0) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline const char* memrimem(const char * src, size_t srcrlen, const char * dst, size_t dstrlen)
{
	if (src == NULL || dst == NULL || srcrlen < dstrlen) {
		return (0);
	}
	else if (srcrlen == dstrlen) {
		return (memricmp(src, dst, dstrlen) == 0 ? (char*)src : 0);
	}
	else {
		for (int i = 0, j = srcrlen - dstrlen; i <= j; i++)
		{
			if (memricmp(src - i, dst, dstrlen) == 0) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline const wchar_t* wmemrimem(const wchar_t * src, size_t srcrlen, const wchar_t * dst, size_t dstrlen)
{
	if (src == NULL || dst == NULL || srcrlen < dstrlen) {
		return (0);
	}
	else if (srcrlen == dstrlen) {
		return (wmemricmp(src, dst, dstrlen) == 0 ? (wchar_t*)src : 0);
	}
	else {
		for (int i = 0, j = srcrlen - dstrlen; i <= j; i++)
		{
			if (wmemricmp(src - i, dst, dstrlen) == 0) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline char* memrpl(const char* src, int srclen, char* dst, int dstlen, const char* r, int rlen, const char* t, int tlen)
{
	int brk = 0;
	int src_cnt = 0;
	int dst_cnt = 0;
	while (src_cnt < srclen && dst_cnt < dstlen)
	{
		brk = 1;
		const char* temp = memmem(src + src_cnt, srclen - src_cnt, r, rlen);
		if (temp) {
			int move_cnt = temp - (src + src_cnt);
			if (move_cnt <= (dstlen - dst_cnt)) {
				memmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;

				if (tlen <= dstlen - dst_cnt) {
					memmove(dst + dst_cnt, t, tlen);
					src_cnt += rlen;
					dst_cnt += tlen;
					brk = 0;
				}
			}
		}
		else {
			int move_cnt = srclen - src_cnt;
			if (move_cnt <= (dstlen - dst_cnt)) {
				memmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;
			}
		}
		if (brk) {
			break;
		}
	}
	return (brk ? 0 : dst);
}

inline wchar_t* wmemrpl(const wchar_t* src, int srclen, wchar_t* dst, int dstlen, const wchar_t* r, int rlen, const wchar_t* t, int tlen)
{
	int brk = 0;
	int src_cnt = 0;
	int dst_cnt = 0;
	while (src_cnt < srclen && dst_cnt < dstlen)
	{
		brk = 1;
		const wchar_t* temp = wmemmem(src + src_cnt, srclen - src_cnt, r, rlen);
		if (temp) {
			int move_cnt = temp - (src + src_cnt);
			if (move_cnt <= (dstlen - dst_cnt)) {
				wmemmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;

				if (tlen <= dstlen - dst_cnt) {
					wmemmove(dst + dst_cnt, t, tlen);
					src_cnt += rlen;
					dst_cnt += tlen;
					brk = 0;
				}
			}
		}
		else {
			int move_cnt = srclen - src_cnt;
			if (move_cnt <= (dstlen - dst_cnt)) {
				wmemmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;
			}
		}
		if (brk) {
			break;
		}
	}
	return (brk ? 0 : dst);
}

inline char* memirpl(const char* src, int srclen, char* dst, int dstlen, const char* r, int rlen, const char* t, int tlen)
{
	int brk = 0;
	int src_cnt = 0;
	int dst_cnt = 0;
	while (src_cnt < srclen && dst_cnt < dstlen)
	{
		brk = 1;
		const char* temp = memimem(src + src_cnt, srclen - src_cnt, r, rlen);
		if (temp) {
			int move_cnt = temp - (src + src_cnt);
			if (move_cnt <= (dstlen - dst_cnt)) {
				memmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;

				if (tlen <= dstlen - dst_cnt) {
					memmove(dst + dst_cnt, t, tlen);
					src_cnt += rlen;
					dst_cnt += tlen;
					brk = 0;
				}
			}
		}
		else {
			int move_cnt = srclen - src_cnt;
			if (move_cnt <= (dstlen - dst_cnt)) {
				memmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;
			}
		}
		if (brk) {
			break;
		}
	}
	return (brk ? 0 : dst);
}

inline wchar_t* wmemirpl(const wchar_t* src, int srclen, wchar_t* dst, int dstlen, const wchar_t* r, int rlen, const wchar_t* t, int tlen)
{
	int brk = 0;
	int src_cnt = 0;
	int dst_cnt = 0;
	while (src_cnt < srclen && dst_cnt < dstlen)
	{
		brk = 1;
		const wchar_t* temp = wmemimem(src + src_cnt, srclen - src_cnt, r, rlen);
		if (temp) {
			int move_cnt = temp - (src + src_cnt);
			if (move_cnt <= (dstlen - dst_cnt)) {
				wmemmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;

				if (tlen <= dstlen - dst_cnt) {
					wmemmove(dst + dst_cnt, t, tlen);
					src_cnt += rlen;
					dst_cnt += tlen;
					brk = 0;
				}
			}
		}
		else {
			int move_cnt = srclen - src_cnt;
			if (move_cnt <= (dstlen - dst_cnt)) {
				wmemmove(dst + dst_cnt, src + src_cnt, move_cnt);
				src_cnt += move_cnt;
				dst_cnt += move_cnt;
			}
		}
		if (brk) {
			break;
		}
	}
	return (brk ? 0 : dst);
}

inline char* memtrimleft(char* src, int srclen, const char* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srclen; i < j; i++)
		{
			if (!memmem(spec, speclen, src + i, 1)) {
				if (i != 0) {
					memmove(src, src + i, srclen - i);
				}
				return src;
			}
		}
		return (0);
	}
}

inline wchar_t* wmemtrimleft(wchar_t* src, int srclen, const wchar_t* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srclen; i < j; i++)
		{
			if (!wmemmem(spec, speclen, src + i, 1)) {
				if (i != 0) {
					wmemmove(src, src + i, srclen - i);
				}
				return src;
			}
		}
		return (0);
	}
}

inline char* memtrimright(char* src, int srclen, const char* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = srclen - 1, j = 0; i >= j; i--)
		{
			if (!memmem(spec, speclen, src + i, 1)) {
				break;
			}
			src[i] = 0;
		}
		return src;
	}
}

inline wchar_t* wmemtrimright(wchar_t* src, int srclen, const wchar_t* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = srclen - 1, j = 0; i >= j; i--)
		{
			if (!wmemmem(spec, speclen, src + i, 1)) {
				break;
			}
			src[i] = 0;
		}
		return src;
	}
}

inline char* memtrim(char* src, int srclen, const char* spec, int speclen)
{
	src = memtrimleft(src, srclen, spec, speclen);
	src = memtrimright(src, srclen, spec, speclen);
	return src;
}

inline wchar_t* wmemtrim(wchar_t* src, int srclen, const wchar_t* spec, int speclen)
{
	src = wmemtrimleft(src, srclen, spec, speclen);
	src = wmemtrimright(src, srclen, spec, speclen);
	return src;
}

inline const char* memskp(const char* src, int srclen, const char* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srclen; i < j; i++)
		{
			if (!memmem(spec, speclen, src + i, 1)) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const wchar_t* wmemskp(const wchar_t* src, int srclen, const wchar_t* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srclen; i < j; i++)
		{
			if (!wmemmem(spec, speclen, src + i, 1)) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const char* memrskp(const char* src, int srcrlen, const char* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srcrlen; i < j; i++)
		{
			if (!memmem(spec, speclen, src - i, 1)) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline const wchar_t* wmemrskp(const wchar_t* src, int srcrlen, const wchar_t* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srcrlen; i < j; i++)
		{
			if (!wmemmem(spec, speclen, src - i, 1)) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline const char* membrk(const char* src, int srclen, const char* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srclen; i < j; i++)
		{
			if (memmem(spec, speclen, src + i, 1)) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const wchar_t* wmembrk(const wchar_t* src, int srclen, const wchar_t* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srclen; i < j; i++)
		{
			if (wmemmem(spec, speclen, src + i, 1)) {
				return (src + i);
			}
		}
		return (0);
	}
}

inline const char* memrbrk(const char* src, int srcrlen, const char* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srcrlen; i < j; i++)
		{
			if (memmem(spec, speclen, src - i, 1)) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline const wchar_t* wmemrbrk(const wchar_t* src, int srcrlen, const wchar_t* spec, int speclen)
{
	if (src == NULL || spec == NULL) {
		return (0);
	}
	else {
		for (int i = 0, j = srcrlen; i < j; i++)
		{
			if (wmemmem(spec, speclen, src - i, 1)) {
				return (src - i);
			}
		}
		return (0);
	}
}

inline const char* stristr(const char* str1, const char* str2)
{
	char *cp = (char *)str1;
	char *s1, *s2;

	if (!*str2)
		return((char *)str1);

	while (*cp)
	{
		s1 = cp;
		s2 = (char *)str2;

		while (*s1 && *s2 && !(chupr(*s1) - chupr(*s2)))
			s1++, s2++;

		if (!*s2)
			return(cp);

		cp++;
	}

	return(NULL);
}
inline const wchar_t* wcsistr(const wchar_t * str1, const wchar_t* str2)
{
	wchar_t *cp = (wchar_t *)str1;
	wchar_t *s1, *s2;

	if (!*str2)
		return((wchar_t *)str1);

	while (*cp)
	{
		s1 = cp;
		s2 = (wchar_t *)str2;

		while (*s1 && *s2 && !(chupr(*s1) - chupr(*s2)))
			s1++, s2++;

		if (!*s2)
			return(cp);

		cp++;
	}

	return(NULL);
}

inline const char* strnstr(const char* src,int len,const char* dst) { return memmem(src,len,dst,strlen(dst)); }
inline const wchar_t* wcsrnstr(const wchar_t* src,int len,const wchar_t* dst) { return wmemrimem(src,len,dst,wcslen(dst)); }
inline const char* strrnistr(const char* src,int len,const char* dst) { return memimem(src,len,dst,strlen(dst)); }
inline const wchar_t* wcsnstr(const wchar_t* src,int len,const wchar_t* dst) { return wmemmem(src,len,dst,wcslen(dst)); }

inline const char* strnrstr(const char* string, int rlen, const char* substr)
{
	return memrmem(string, rlen, substr, strlen(substr));
}

inline const wchar_t* wcsnrstr(const wchar_t* string, int rlen, const wchar_t* substr)
{
	return wmemrmem(string, rlen, substr, wcslen(substr));
}

inline const char* strrstr(const char* str1, const char* str2)
{
	int len = strlen(str1);
	return strnrstr(str1 + len - 1, len, str2);
}

inline const wchar_t* wcsrstr(const wchar_t * str1, const wchar_t* str2)
{
	int len = wcslen(str1);
	return wcsnrstr(str1 + len - 1, len, str2);
}

inline const char* strnirstr(const char* string, int len, const char* spec)
{
	return memrimem(string, len, spec, strlen(spec));
}

inline const wchar_t* wcsnirstr(const wchar_t* string, int len, const wchar_t* spec)
{
	return wmemrimem(string, len, spec, wcslen(spec));
}

inline const char* strirstr(const char* str1, const char* str2)
{
	int len = strlen(str1);
	return strnirstr(str1 + len - 1, len, str2);
}

inline const wchar_t* wcsirstr(const wchar_t * str1, const wchar_t* str2)
{
	int len = wcslen(str1);
	return wcsnirstr(str1 + len - 1, len, str2);
}

inline const char* strichr(const char * string, int ch)
{
	while (*string && (chupr(*string) != chupr(ch)))
		string++;

	if (chupr(*string) == chupr(ch))
		return string;
	return(NULL);
}

inline const wchar_t* wcsichr(const wchar_t * string, int ch)
{
	while (*string && (chupr(*string) != chupr(ch)))
		string++;

	if (chupr(*string) == chupr(ch))
		return string;
	return(NULL);
}


inline const char* strnchr(const char* string, int len, char ch)
{
	while (len-- > 0)
	{
		if (*string != ch) {
			string++;
		}
		else {
			break;
		}
	}
	return ((len >= 0) ? string : 0);
}

inline const wchar_t* wcsnchr(const wchar_t* string, int len, wchar_t ch)
{
	while (len-- > 0)
	{
		if (*string != ch) {
			string++;
		}
		else {
			break;
		}
	}
	return ((len >= 0) ? string : 0);
}

inline const char* strnichr(const char* string, int len, char ch)
{
	while (len-- > 0)
	{
		if (chupr(*string) != chupr(ch)) {
			string++;
		}
		else {
			break;
		}
	}
	return ((len >= 0) ? string : 0);
}

inline const wchar_t* wcsnichr(const wchar_t* string, int len, wchar_t ch)
{
	while (len-- > 0)
	{
		if (chupr(*string) != chupr(ch)) {
			string++;
		}
		else {
			break;
		}
	}
	return ((len >= 0) ? string : 0);
}

inline char* strtrimleft(char* string, const char* spec)
{
	char* str = string;
	while (*str && strchr(spec, *str))
		str++;

	if (str != string)
		memmove(string, str, strlen(string) - (str - string));

	return string;
}

inline wchar_t* wcstrimleft(wchar_t* string, const wchar_t* spec)
{
	wchar_t* str = string;
	while (*str && wcschr(spec, *str))
		str++;

	if (str != string)
		wmemmove(string, str, wcslen(string) - (str - string));

	return string;
}

inline char* strntrimleft(char* string, int len, const char* spec)
{
	return memtrimleft(string, len, spec, strlen(spec));
}

inline wchar_t* wcsntrimleft(wchar_t* string, int len, const wchar_t* spec)
{
	return wmemtrimleft(string, len, spec, wcslen(spec));
}

inline char* strtrimright(char* string, const char* spec)
{
	int len = strlen(string);
	char* str = string + len;
	while (str != string && strchr(spec, *str))
		str--;

	if (str - string < len)
		*str = 0;

	return string;
}

inline wchar_t* wcstrimright(wchar_t* string, const wchar_t* spec)
{
	int len = wcslen(string);
	wchar_t* str = string + len;
	while (str != string && wcschr(spec, *str))
		str--;

	if (str - string < len)
		*str = 0;

	return string;
}

inline char* strntrimright(char* string, int len, const char* spec)
{
	return memtrimright(string, len, spec, strlen(spec));
}

inline wchar_t* wcsntrimright(wchar_t* string, int len, const wchar_t* spec)
{
	return wmemtrimright(string, len, spec, wcslen(spec));
}

inline char* strtrim(char* string, const char* spec)
{
	return strtrimright(strtrimleft(string, spec), spec);
}

inline wchar_t* wcstrim(wchar_t* string, const wchar_t* spec)
{
	return wcstrimright(wcstrimleft(string, spec), spec);
}

inline char* strntrim(char* string, int len, const char* spec)
{
	return memtrim(string, len, spec, strlen(spec));
}

inline wchar_t* wcsntrim(wchar_t* string, int len, const wchar_t* spec)
{
	return wmemtrim(string, len, spec, wcslen(spec));
}

inline char* strrpl(char* string, const char* r, const char* t)
{
	int rlen = strlen(r);
	int tlen = strlen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		char* str = string;
		while (*str)
		{
			if (strncmp(str, r, rlen) == 0) {
				strncpy(str, t, tlen);
				if (rtspace) {
					strcpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline wchar_t* wcsrpl(wchar_t* string, const wchar_t* r, const wchar_t* t)
{
	int rlen = wcslen(r);
	int tlen = wcslen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		wchar_t* str = string;
		while (*str)
		{
			if (wcsncmp(str, r, rlen) == 0) {
				wcsncpy(str, t, tlen);
				if (rtspace) {
					wcscpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline char* strnrpl(char* string, int len, const char* r, const char* t)
{
	int rlen = strlen(r);
	int tlen = strlen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		char* str = string;
		while (len-- > 0)
		{
			if (strncmp(str, r, rlen) == 0) {
				strncpy(str, t, tlen);
				if (rtspace) {
					strcpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline wchar_t* wcsnrpl(wchar_t* string, int len, const wchar_t* r, const wchar_t* t)
{
	int rlen = wcslen(r);
	int tlen = wcslen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		wchar_t* str = string;
		while (len-- > 0)
		{
			if (wcsncmp(str, r, rlen) == 0) {
				wcsncpy(str, t, tlen);
				if (rtspace) {
					wcscpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline char* strirpl(char* string, const char* r, const char* t)
{
	int rlen = strlen(r);
	int tlen = strlen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		char* str = string;
		while (*str)
		{
			if (strnicmp(str, r, rlen) == 0) {
				strncpy(str, t, tlen);
				if (rtspace) {
					strcpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline wchar_t* wcsirpl(wchar_t* string, const wchar_t* r, const wchar_t* t)
{
	int rlen = wcslen(r);
	int tlen = wcslen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		wchar_t* str = string;
		while (*str)
		{
			if (wcsnicmp(str, r, rlen) == 0) {
				wcsncpy(str, t, tlen);
				if (rtspace) {
					wcscpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline char* strnirpl(char* string, int len, const char* r, const char* t)
{
	int rlen = strlen(r);
	int tlen = strlen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		char* str = string;
		while (len-- > 0)
		{
			if (strnicmp(str, r, rlen) == 0) {
				strncpy(str, t, tlen);
				if (rtspace) {
					strcpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline wchar_t* wcsnirpl(wchar_t* string, int len, const wchar_t* r, const wchar_t* t)
{
	int rlen = wcslen(r);
	int tlen = wcslen(t);
	int rtspace = rlen - tlen;
	if (rtspace < 0) {
		return 0;
	}
	else {
		wchar_t* str = string;
		while (len-- > 0)
		{
			if (wcsnicmp(str, r, rlen) == 0) {
				wcsncpy(str, t, tlen);
				if (rtspace) {
					wcscpy(str + tlen, str + rlen);
				}
				str += tlen;
			}
			else {
				str++;
			}
		}
		return string;
	}
}

inline char* strrpl(char* string, char r, char t)
{
	char* str = string;
	while (*str)
	{
		if (*str == r) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline wchar_t* wcsrpl(wchar_t* string, wchar_t r, wchar_t t)
{
	wchar_t* str = string;
	while (*str)
	{
		if (*str == r) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline char* strnrpl(char* string, int len, char r, char t)
{
	char* str = string;
	while (len-- > 0)
	{
		if (*str == r) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline wchar_t* wcsnrpl(wchar_t* string, int len, wchar_t r, wchar_t t)
{
	wchar_t* str = string;
	while (len-- > 0)
	{
		if (*str == r) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline char* strirpl(char* string, char r, char t)
{
	char* str = string;
	while (*str)
	{
		if (chupr(*str) == chupr(r)) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline wchar_t* wcsirpl(wchar_t* string, wchar_t r, wchar_t t)
{
	wchar_t* str = string;
	while (*str)
	{
		if (chupr(*str) == chupr(r)) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline char* strnirpl(char* string, int len, char r, char t)
{
	char* str = string;
	while (len-- > 0)
	{
		if (chupr(*str) == chupr(r)) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline wchar_t* wcsnirpl(wchar_t* string, int len, wchar_t r, wchar_t t)
{
	wchar_t* str = string;
	while (len-- > 0)
	{
		if (chupr(*str) == chupr(r)) {
			*str = t;
		}
		str++;
	}
	return string;
}

inline const char* strskp(const char* string, char spec)
{
	while (*string && spec == *string)
		string++;

	return (*string ? string : 0);
}

inline const wchar_t* wcsskp(const wchar_t* string, wchar_t spec)
{
	while (*string && spec == *string)
		string++;

	return (*string ? string : 0);
}

inline const char* strnskp(const char* string, int len, char spec)
{
	while (len-- && spec == *string)
		string++;

	return ((len >= 0) ? string : 0);
}

inline const wchar_t* wcsnskp(const wchar_t* string, int len, wchar_t spec)
{
	while (len-- && spec == *string)
		string++;

	return ((len >= 0) ? string : 0);
}

inline const char* strskp(const char* string, const char* spec)
{
	while (*string && strchr(spec, *string))
		string++;

	return (*string ? string : 0);
}

inline const wchar_t* wcsskp(const wchar_t* string, const wchar_t* spec)
{
	while (*string && wcschr(spec, *string))
		string++;

	return (*string ? string : 0);
}

inline const char* strnskp(const char* string, int len, const char* spec)
{
	return memskp(string, len, spec, strlen(spec));
}

inline const wchar_t* wcsnskp(const wchar_t* string, int len, const wchar_t* spec)
{
	return wmemskp(string, len, spec, wcslen(spec));
}

inline const char* strrskp(const char* string, int rlen, const char* spec)
{
	return memrskp(string, rlen, spec, strlen(spec));
}

inline const wchar_t* wcsrskp(const wchar_t* string, int rlen, const wchar_t* spec)
{
	return wmemrskp(string, rlen, spec, wcslen(spec));
}

inline const char* strbrk(const char* string, char spec)
{
	while (*string && spec != *string)
		string++;

	return (*string ? string : 0);
}

inline const wchar_t* wcsbrk(const wchar_t* string, wchar_t spec)
{
	while (*string && spec != *string)
		string++;

	return (*string ? string : 0);
}

inline const char* strnbrk(const char* string, int len, char spec)
{
	while (len-- && spec != *string)
		string++;

	return ((len >= 0) ? string : 0);
}

inline const wchar_t* wcsnbrk(const wchar_t* string, int len, wchar_t spec)
{
	while (len-- && spec != *string)
		string++;

	return ((len >= 0) ? string : 0);
}

inline const char* strrbrk(const char* string, int rlen, char spec)
{
	while (rlen-- && spec != *string)
		string--;

	return ((rlen >= 0) ? string : 0);
}

inline const wchar_t* wcsrbrk(const wchar_t* string, int rlen, wchar_t spec)
{
	while (rlen-- && spec != *string)
		string--;

	return ((rlen >= 0) ? string : 0);
}

inline const char* strbrk(const char* string, const char* spec)
{
	while (*string && !strchr(spec, *string))
		string++;

	return (*string ? string : 0);
}

inline const wchar_t* wcsbrk(const wchar_t* string, const wchar_t* spec)
{
	while (*string && !wcschr(spec, *string))
		string++;

	return (*string ? string : 0);
}

inline const char* strnbrk(const char* string, int len, const char* spec)
{
	return membrk(string, len, spec, strlen(spec));
}

inline const wchar_t* wcsnbrk(const wchar_t* string, int len, const wchar_t* spec)
{
	return wmembrk(string, len, spec, wcslen(spec));
}

inline const char* strrbrk(const char* string, const char* spec)
{
	int len = strlen(string);
	return memrbrk(string + len - 1, len, spec, strlen(spec));
}

inline const wchar_t* wcsrbrk(const wchar_t* string, const wchar_t* spec)
{
	int len = wcslen(string);
	return wmemrbrk(string + len - 1, len, spec, wcslen(spec));
}

inline const char* strnrbrk(const char* string, int rlen, const char* spec)
{
	return memrbrk(string, rlen, spec, strlen(spec));
}

inline const wchar_t* wcsnrbrk(const wchar_t* string, int rlen, const wchar_t* spec)
{
	return wmemrbrk(string, rlen, spec, wcslen(spec));
}

// #ifdef UNICODE
// #define _tcsrcmp wcsrcmp
// #define _tcsrnicmp wcsrnicmp
// #else
// #define _tcsrcmp strrcmp
// #define _tcsrnicmp strrnicmp
// #endif//
// #ifdef UNICODE
// #define _tcsnstr wcsnstr
// #define _tcsistr wcsistr
// #define _tcsnistr wcsnistr
// #else
// #define _tcsnstr strnstr
// #define _tcsistr stristr
// #define _tcsnistr strnistr
// #endif//
// #ifdef UNICODE
// #define _tcsrstr wcsrstr
// #else
// #define _tcsrstr strrstr
// #endif//
// #ifdef UNICODE
// #define _tcsnrstr wcsnrstr
// #else
// #define _tcsnrstr strnrstr
// #endif//
// #ifdef UNICODE
// #define _tcsirstr wcsirstr
// #else
// #define _tcsirstr strirstr
// #endif//
// #ifdef UNICODE
// #define _tcsnirstr wcsnirstr
// #else
// #define _tcsnirstr strnirstr
// #endif//
// #ifdef UNICODE
// #define _tcsichr wcsichr
// #else
// #define _tcsichr strichr
// #endif//
// #ifdef UNICODE
// #define _tcsnchr wcsnchr
// #else
// #define _tcsnchr strnchr
// #endif//
// #ifdef UNICODE
// #define _tcsnichr wcsnichr
// #else
// #define _tcsnichr strnichr
// #endif//
// #ifdef UNICODE
// #define _tcstrimleft wcstrimleft
// #else
// #define _tcstrimleft strtrimleft
// #endif//
// #ifdef UNICODE
// #define _tcsntrimleft wcsntrimleft
// #else
// #define _tcsntrimleft strntrimleft
// #endif//
// #ifdef UNICODE
// #define _tcstrimright wcstrimright
// #else
// #define _tcstrimright strtrimright
// #endif//
// #ifdef UNICODE
// #define _tcsntrimright wcsntrimright
// #else
// #define _tcsntrimright strntrimright
// #endif//
// #ifdef UNICODE
// #define _tcstrim wcstrim
// #else
// #define _tcstrim strtrim
// #endif//
// #ifdef UNICODE
// #define _tcsntrim wcsntrim
// #else
// #define _tcsntrim strntrim
// #endif//
// #ifdef UNICODE
// #define _tcsrep wcsrep
// #else
// #define _tcsrep strrep
// #endif//
// #ifdef UNICODE
// #define _tcsnrep wcsnrep
// #else
// #define _tcsnrep strnrep
// #endif//
// #ifdef UNICODE
// #define _tcsirep wcsirep
// #else
// #define _tcsirep strirep
// #endif//
// #ifdef UNICODE
// #define _tcsnirep wcsnirep
// #else
// #define _tcsnirep strnirep
// #endif//
// #ifdef UNICODE
// #define _tcsrpl wcsrpl
// #else
// #define _tcsrpl strrpl
// #endif//
// #ifdef UNICODE
// #define _tcsnrpl wcsnrpl
// #else
// #define _tcsnrpl strnrpl
// #endif//
// #ifdef UNICODE
// #define _tcsirpl wcsirpl
// #else
// #define _tcsirpl strirpl
// #endif//
// #ifdef UNICODE
// #define _tcsnirpl wcsnirpl
// #else
// #define _tcsnirpl strnirpl
// #endif//
// #ifdef UNICODE
// #define _tcsskp wcsskp
// #else
// #define _tcsskp strskp
// #endif//
// #ifdef UNICODE
// #define _tcsnskp wcsnskp
// #else
// #define _tcsnskp strnskp
// #endif//
// #ifdef UNICODE
// #define _tcsskip wcsskip
// #else
// #define _tcsskip strskip
// #endif//
// #ifdef UNICODE
// #define _tcsnskip wcsnskip
// #else
// #define _tcsnskip strnskip
// #endif//
// #ifdef UNICODE
// #define _tcsrskip wcsrskip
// #else
// #define _tcsrskip strrskip
// #endif//
// #ifdef UNICODE
// #define _tcsbrk wcsbrk
// #else
// #define _tcsbrk strbrk
// #endif//
// #ifdef UNICODE
// #define _tcsnbrk wcsnbrk
// #else
// #define _tcsnbrk strnbrk
// #endif//
// #ifdef UNICODE
// #define _tcsrbrk wcsrbrk
// #else
// #define _tcsrbrk strrbrk
// #endif//
// #ifdef UNICODE
// #define _tcsbrk wcsbrk
// #else
// #define _tcsbrk strbrk
// #endif//
// #ifdef UNICODE
// #define _tcsnbrk wcsnbrk
// #else
// #define _tcsnbrk strnbrk
// #endif//
// #ifdef UNICODE
// #define _tcsrbrk wcsrbrk
// #else
// #define _tcsrbrk strrbrk
// #endif//
// #ifdef UNICODE
// #define _tcsnrbrk wcsnrbrk
// #else
// #define _tcsnrbrk strnrbrk
// #endif//

	template<typename Target>
	inline Target strto(const std::string& arg, const Target& def = Target())
	{
		if (!arg.empty()) {
			try
			{
				Target o;
				std::stringstream ss;
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

	template<typename Target>
	inline Target wcsto(const std::wstring& arg, const Target& def = Target())
	{
		if (!arg.empty()) {
			try 
			{
				Target o;
				std::wstringstream ss;
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
	inline std::string tostr(const Source& arg)
	{
		std::ostringstream ss;
		ss << arg;
		return ss.str();
	}

	template<typename Source>
	inline std::wstring towcs(const Source& arg)
	{
		std::wostringstream ss;
		ss << arg;
		return ss.str();
	}

	template<typename Source>
	inline std::string tostrex(const Source& arg, int p = -1, int w = -1, char c = '0')
	{
		std::ostringstream ss;
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

	template<typename Source>
	inline std::wstring towcsex(const Source& arg, int p = -1, int w = -1, wchar_t c = '0')
	{
		std::wostringstream ss;
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

#endif//_H_XSTR_H_