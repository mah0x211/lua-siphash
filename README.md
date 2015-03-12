# lua-siphash

siphash module.

implementation depends on   
`src/siphash.h`: https://github.com/mah0x211/siphash


## Installation

```sh
luarocks install siphash --from=http://mah0x211.github.io/rocks/
```

## Functions

### hex, err = encode24/encode48( src:str [, key:str] )

**Parameters**

- `src:str`: message string.
- `key:str`: 128 bit secret key string.


**Returns**

1. `hex:str`: hex-encoded string on success. or, a nil on failure.
2. `err:str`: error message about a key argument length.



