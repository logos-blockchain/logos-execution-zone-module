{
  description = "Logos Blockchain Module - Qt6 Plugin";

  inputs = {
    nixpkgs.follows = "logos-liblogos/nixpkgs";

    logos-liblogos.url = "github:logos-co/logos-liblogos";
    logos-core.url = "github:logos-co/logos-cpp-sdk";

    logos-execution-zone.url = "github:logos-blockchain/lssa";

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";
  };

  outputs =
    {
      self,
      nixpkgs,
      logos-core,
      logos-execution-zone,
      logos-module-viewer,
      ...
    }:
    let
      lib = nixpkgs.lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-windows"
      ];

      forAll = lib.genAttrs systems;

      mkPkgs = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAll (
        system:
        let
          pkgs = mkPkgs system;
          llvmPkgs = pkgs.llvmPackages;

          logosCore = logos-core.packages.${system}.default;
          logosExecutionZoneWalletPackage = logos-execution-zone.packages.${system}.wallet;

          logosExecutionZoneWalletModulePackage = pkgs.stdenv.mkDerivation {
            pname = "logos-execution-zone-module";
            version = "dev";
            src = ./.;

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.ninja
              pkgs.pkg-config
              pkgs.qt6.wrapQtAppsHook
            ];

            buildInputs = [
              pkgs.qt6.qtbase
              pkgs.qt6.qtremoteobjects
              pkgs.qt6.qttools
              llvmPkgs.clang
              llvmPkgs.libclang
              logosExecutionZoneWalletPackage
            ]
            ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.libiconv
              pkgs.cacert
            ];

            LIBCLANG_PATH = "${llvmPkgs.libclang.lib}/lib";
            CLANG_PATH = "${llvmPkgs.clang}/bin/clang";
            SSL_CERT_FILE = lib.optionalString pkgs.stdenv.isDarwin "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            cmakeFlags = [
              "-DLOGOS_CORE_ROOT=${logosCore}"
              "-DLOGOS_EXECUTION_ZONE_WALLET_LIB=${logosExecutionZoneWalletPackage}/lib"
              "-DLOGOS_EXECUTION_ZONE_WALLET_INCLUDE=${logosExecutionZoneWalletPackage}/include"
            ];
        };
        in
        {
          lib = logosExecutionZoneWalletModulePackage;
          default = logosExecutionZoneWalletModulePackage;
        }
      );

      apps = forAll (
        system:
        let
          pkgs = mkPkgs system;
          logosExecutionZoneWalletModuleLib = self.packages.${system}.lib;
          logosModuleViewerPackage = logos-module-viewer.packages.${system}.default;
          extension = if pkgs.stdenv.isDarwin then "dylib"
            else if pkgs.stdenv.hostPlatform.isWindows then "dll"
            else "so";
          inspectModule = {
            type = "app";
            program =
              "${pkgs.writeShellScriptBin "inspect-module" ''
                exec ${logosModuleViewerPackage}/bin/logos-module-viewer \
                  --module ${logosExecutionZoneWalletModuleLib}/lib/liblogos-execution-zone-wallet-module.${extension}
              ''}/bin/inspect-module";
          };
        in
        {
          inspect-module = inspectModule;
          default = inspectModule;
        }
      );

      devShells = forAll (
        system:
        let
          pkgs = mkPkgs system;
          pkg = self.packages.${system}.default;
          logosCorePackage = logos-core.packages.${system}.default;
          logosExecutionZoneWalletPackage = logos-execution-zone.packages.${system}.wallet;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ pkg ];

            inherit (pkg)
              LIBCLANG_PATH
              CLANG_PATH;

            LOGOS_CORE_ROOT = "${logosCorePackage}";
            LOGOS_EXECUTION_ZONE_WALLET_LIB = "${logosExecutionZoneWalletPackage}/lib";
            LOGOS_EXECUTION_ZONE_WALLET_INCLUDE = "${logosExecutionZoneWalletPackage}/include";

            shellHook = ''
              BLUE='\e[1;34m'
              GREEN='\e[1;32m'
              RESET='\e[0m'

              echo -e "\n''${BLUE}=== Logos Execution Zone Module Development Environment ===''${RESET}"
              echo -e "''${GREEN}LOGOS_CORE_ROOT:''${RESET}                     $LOGOS_CORE_ROOT"
              echo -e "''${GREEN}LOGOS_EXECUTION_ZONE_WALLET_LIB:''${RESET}     $LOGOS_EXECUTION_ZONE_WALLET_LIB"
              echo -e "''${GREEN}LOGOS_EXECUTION_ZONE_WALLET_INCLUDE:''${RESET} $LOGOS_EXECUTION_ZONE_WALLET_INCLUDE"
              echo -e "''${BLUE}---------------------------------------------------------''${RESET}"
            '';
          };
        }
      );
    };
}
