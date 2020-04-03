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
#ifndef _H_XHTTP3_IMPL_H_
#define _H_XHTTP3_IMPL_H_

#include "XSocketImpl.h"
#include "XHttp2Impl.h"
#include "XQuicImpl.h"
#include <nghttp3/nghttp3.h>

namespace XSocket
{

namespace
{

template <typename T, size_t N1, size_t N2>
constexpr nghttp3_nv make_nv(const T (&name)[N1], const T (&value)[N2])
{
    return nghttp3_nv{(uint8_t *)name, (uint8_t *)value, N1 - 1, N2 - 1,
                      NGHTTP3_NV_FLAG_NONE};
}

template <typename T, size_t N, typename S>
constexpr nghttp3_nv make_nv(const T (&name)[N], const S &value)
{
    return nghttp3_nv{(uint8_t *)name, (uint8_t *)value.data(), N - 1,
                      value.size(), NGHTTP3_NV_FLAG_NONE};
}

template <typename S1, typename S2>
constexpr nghttp3_nv make_nv(const S1 &name, const S2 &value)
{
    return nghttp3_nv{(uint8_t *)name.data(), (uint8_t *)value.data(),
                      name.size(), value.size(), NGHTTP3_NV_FLAG_NONE};
}

} // namespace

} // namespace XSocket

#endif //_H_XHTTP3_IMPL_H_