default: build

configure:
    cmake -S . -B build -G Ninja \
      ${LOGOS_CORE_ROOT:+-DLOGOS_CORE_ROOT="$LOGOS_CORE_ROOT"} \
      ${LOGOS_EXECUTION_ZONE_WALLET_LIB:+-DLOGOS_EXECUTION_ZONE_WALLET_LIB="$LOGOS_EXECUTION_ZONE_WALLET_LIB"} \
      ${LOGOS_EXECUTION_ZONE_WALLET_INCLUDE:+-DLOGOS_EXECUTION_ZONE_WALLET_INCLUDE="$LOGOS_EXECUTION_ZONE_WALLET_INCLUDE"}

build: configure
    cmake --build build --parallel --target liblogos-execution-zone-wallet-module

clean:
    rm -rf build result

rebuild: clean build

nix:
    nix develop

prettify:
    nix shell nixpkgs#clang-tools -c clang-format -i src/**.cpp src/**.h

unicode-logs file:
    perl -pe 's/\\u([0-9A-Fa-f]{4})/chr(hex($1))/ge' {{file}} | less -R
