default: build

configure:
    cmake -S . -B build -G Ninja \
      ${LOGOS_CORE_ROOT:+-DLOGOS_CORE_ROOT="$LOGOS_CORE_ROOT"} \
      ${LEZ_CORE_LIB:+-DLEZ_CORE_LIB="$LEZ_CORE_LIB"} \
      ${LEZ_CORE_INCLUDE:+-DLEZ_CORE_INCLUDE="$LEZ_CORE_INCLUDE"}

build: configure
    cmake --build build --parallel --target lez_core_module_plugin

clean:
    rm -rf build result

rebuild: clean build

nix:
    nix develop

prettify:
    nix shell nixpkgs#clang-tools -c clang-format -i src/**.cpp src/**.h

unicode-logs file:
    perl -pe 's/\\u([0-9A-Fa-f]{4})/chr(hex($1))/ge' {{file}} | less -R
