{
  description = "Logos Execution Zone Core Module";

  # Pull pre-built artifacts from the self-hosted Logos Attic cache(Nix binary cache).
  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [ "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU=" ];
  };

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    nix-bundle-lgx.url = "github:logos-co/nix-bundle-lgx";
    # the ref commit is 0.3.0 + r0 linking fix on `main`
    logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?rev=411adc8fdb3f4c3af64354c4fc26d3e4a6a3d3f4";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
      externalLibInputs = {
        wallet_ffi = {
          input = inputs.logos-execution-zone;
          packages.default = "wallet";
        };
      };
      tests = {
        dir = ./tests;
        mockCLibs = [ "wallet_ffi" ];
      };
    };
}
