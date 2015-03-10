/*
 *  Copyright (C) 2014 Masatoshi Teruya
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 *  siphash.c
 *  lua-siphash
 *
 *  Created by Masatoshi Teruya on 14/09/19.
 *
 */

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <lua.h>
#include <lauxlib.h>
#include "siphash.h"

#define lstate_fn2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushcfunction(L,v); \
    lua_rawset(L,-3); \
}while(0)


// buf size must be larger than len*2
static const char HEXCHR[] = "0123456789abcdef";

#define _digest2hex(ptr,digest) ({\
    (ptr)[0] = HEXCHR[digest >> 4]; \
    (ptr)[1] = HEXCHR[digest & 0xf]; \
})

#define digest2hex( buf, hash ) do { \
    uint8_t *ptr = buf; \
    uint8_t *digest = (uint8_t*)&hash; \
    _digest2hex( ptr, digest[0] ); \
    _digest2hex( ptr+2, digest[1] ); \
    _digest2hex( ptr+4, digest[2] ); \
    _digest2hex( ptr+6, digest[3] ); \
    _digest2hex( ptr+8, digest[4] ); \
    _digest2hex( ptr+10, digest[5] ); \
    _digest2hex( ptr+12, digest[6] ); \
    _digest2hex( ptr+14, digest[7] ); \
}while(0)


static inline int encode_lua( lua_State *L, const uint8_t blk, const uint8_t fin )
{
    size_t len = 0;
    const char *src = luaL_checklstring( L, 1, &len );
    size_t klen = 0;
    const char *keystr = luaL_checklstring( L, 2, &klen );
    uint64_t key[2] = {0};
    uint64_t hash = 0;
    uint8_t hex[16] = {0};
    
    // key must be 128 bit length
    if( klen > 16 ){
        lua_pushnil( L );
        lua_pushstring( L, "key must be 128 bit length" );
        return 2;
    }
    
    memcpy( (void*)key, (void*)keystr, klen );
    hash = siphash( blk, fin, key, src, len );
    // to hex string
    digest2hex( hex, hash );

    lua_pushlstring( L, (const char*)hex, 16 );

    return 1;
}


static int encode24_lua( lua_State *L ){
    return encode_lua( L, 2, 4 );
}


static int encode48_lua( lua_State *L ){
    return encode_lua( L, 4, 8 );
}


LUALIB_API int luaopen_siphash( lua_State *L )
{
    struct luaL_Reg method[] = {
        { "encode24", encode24_lua },
        { "encode48", encode48_lua },
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = method;

    lua_newtable( L );
    do {
        lstate_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    } while( ptr->name );

    return 1;
}
