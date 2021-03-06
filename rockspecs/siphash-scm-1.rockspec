package = "siphash"
version = "scm-1"
source = {
    url = "git://github.com/mah0x211/lua-siphash.git"
}
description = {
    summary = "siphash module",
    homepage = "https://github.com/mah0x211/lua-siphash",
    license = "MIT/X11",
    maintainer = "Masatoshi Teruya"
}
dependencies = {
    "lua >= 5.1"
}
build = {
    type = "builtin",
    modules = {
        siphash = {
            sources = { "src/siphash.c" },
        }
    }
}

