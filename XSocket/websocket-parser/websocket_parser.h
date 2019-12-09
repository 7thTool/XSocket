#ifndef WEBSOCKET_PARSER_H
#define WEBSOCKET_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>
#if defined(_WIN32) && !defined(__MINGW32__) && \
  (!defined(_MSC_VER) || _MSC_VER<1600) && !defined(__WINE__)
#include <BaseTsd.h>
#include <stddef.h>
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

#define WEBSOCKET_UUID   "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct websocket_parser websocket_parser;
typedef struct websocket_parser_settings websocket_parser_settings;

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
enum {
    // opcodes
    WS_OP_CONTINUE = 0x0,
    WS_OP_TEXT     = 0x1,
    WS_OP_BINARY   = 0x2,
    WS_OP_CLOSE    = 0x8,
    WS_OP_PING     = 0x9,
    WS_OP_PONG     = 0xA,
};

#define WS_OP_MASK 0xF
#define WS_FINAL_FRAME 0x10
#define WS_FIN WS_FINAL_FRAME
#define WS_HAS_MASK 0x20

typedef int (*websocket_data_cb) (websocket_parser*, const char * at, size_t length);
typedef int (*websocket_cb) (websocket_parser*);

struct websocket_parser {
    uint32_t        state;
    uint8_t         flags;

    char            mask[4];
    uint8_t         mask_offset;

    size_t   length;
    size_t   require;
    size_t   offset;

    void * data;
};

struct websocket_parser_settings {
    websocket_cb      on_frame_header;
    websocket_data_cb on_frame_body;
    websocket_cb      on_frame_end;
};

void websocket_parser_init(websocket_parser *parser);
void websocket_parser_settings_init(websocket_parser_settings *settings);
uint64_t websocket_parser_execute(
    websocket_parser * parser,
    const websocket_parser_settings *settings,
    const char * data,
    uint64_t len
);

// Apply XOR mask (see https://tools.ietf.org/html/rfc6455#section-5.3) and store mask's offset
void websocket_parser_decode(char * dst, const char * src, uint64_t len, websocket_parser * parser);

// Apply XOR mask (see https://tools.ietf.org/html/rfc6455#section-5.3) and return mask's offset
uint8_t websocket_decode(char * dst, const char * src, uint64_t len, const char mask[4], uint8_t mask_offset);
#define websocket_encode(dst, src, len, mask, mask_offset) websocket_decode(dst, src, len, mask, mask_offset)

// Calculate frame size using flags and data length
uint64_t websocket_calc_frame_size(int flags, uint64_t data_len);

// Create string representation of frame header
uint64_t websocket_build_frame_header(char * frame, int flags, const char mask[4], uint64_t data_len);

// Create string representation of frame
uint64_t websocket_build_frame(char * frame, int flags, const char mask[4], const char * data, uint64_t data_len);

#define websocket_parser_get_opcode(p) (p->flags & WS_OP_MASK)
#define websocket_parser_has_mask(p) (p->flags & WS_HAS_MASK)
#define websocket_parser_has_final(p) (p->flags & WS_FIN)

#ifdef __cplusplus
}
#endif
#endif //WEBSOCKET_PARSER_H
