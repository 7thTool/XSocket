#ifndef WS_PARSER
#define WS_PARSER
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#if defined(_WIN32) && !defined(__MINGW32__) && \
  (!defined(_MSC_VER) || _MSC_VER<1600) && !defined(__WINE__)
#include <BaseTsd.h>
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-------+-+-------------+-------------------------------+
//  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//  | |1|2|3|       |K|             |                               |
//  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//  |     Extended payload length continued, if payload len == 127  |
//  + - - - - - - - - - - - - - - - +-------------------------------+
//  |                               |Masking-key, if MASK set to 1  |
//  +-------------------------------+-------------------------------+
//  | Masking-key (continued)       |          Payload Data         |
//  +-------------------------------- - - - - - - - - - - - - - - - +
//  :                     Payload Data continued ...                :
//  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//  |                     Payload Data continued ...                |
//  +---------------------------------------------------------------+
typedef enum {
    WS_FRAME_TEXT   = 0x1,
    WS_FRAME_BINARY = 0x2,
    WS_FRAME_CLOSE  = 0x8,
    WS_FRAME_PING   = 0x9,
    WS_FRAME_PONG   = 0xA,
}
ws_frame_type_t;

// marks
#define WS_FLAG_FIN 0x10
#define WS_FLAG_MASK 0x20

typedef struct {
    int(*on_data_begin)     (void*, ws_frame_type_t);
    int(*on_data_payload)   (void*, const char*, size_t);
    int(*on_data_end)       (void*);
    int(*on_control_begin)  (void*, ws_frame_type_t);
    int(*on_control_payload)(void*, const char*, size_t);
    int(*on_control_end)    (void*);
}
ws_parser_callbacks_t;

typedef struct {
    uint64_t bytes_remaining;
    uint8_t mask[4];
    uint8_t fragment  : 1;
    uint8_t fin       : 1;
    uint8_t control   : 1;
    uint8_t mask_flag : 1;
    uint8_t mask_pos  : 2;
    uint8_t state     : 5;
}
ws_parser_t;

#define WS_PARSER_ERROR_CODES(XX) \
    XX(WS_OK,                    0) \
    XX(WS_RESERVED_BITS_SET,    -1) \
    XX(WS_INVALID_OPCODE,       -2) \
    XX(WS_INVALID_CONTINUATION, -3) \
    XX(WS_CONTROL_TOO_LONG,     -4) \
    XX(WS_NON_CANONICAL_LENGTH, -5) \
    XX(WS_FRAGMENTED_CONTROL,   -6) \

enum {
    #define XX(name, code) name = code,
    WS_PARSER_ERROR_CODES(XX)
    #undef XX
};

void
ws_parser_init(ws_parser_t* parser);

int
ws_parser_execute(
    ws_parser_t* parser,
    const ws_parser_callbacks_t* callbacks,
    void* data,
    char* buff /* mutates! */,
    size_t len);

const char*
ws_parser_error(int rc);

size_t 
ws_builder_calc_size(int flags /*eg. WS_FRAME_TEXT|WS_FLAG_FIN*/, 
    size_t len);

size_t 
ws_builder_execute(char * out, 
    int flags /*eg. WS_FRAME_TEXT|WS_FLAG_FIN*/, 
    const uint8_t mask[4], 
    const char * buf, 
    size_t len);

#ifdef __cplusplus
}
#endif
#endif
