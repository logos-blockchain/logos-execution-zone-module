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
    lez-rust-overlay.url = "github:oxalica/rust-overlay/b2ccad3b67335d368eef49ec48b9c8166858e73d";
    logos-execution-zone = {
      url = "github:logos-blockchain/logos-execution-zone?ref=Pravdyvy/sequencer-ffi-integration-nix-update";
      inputs.rust-overlay.follows = "lez-rust-overlay";
    };
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
      externalLibInputs = {
        core_ffi = {
          input = inputs.logos-execution-zone;
          packages.default = "core";
        };
      };
      tests = {
        dir = ./tests;
        mockCLibs = [ "core_ffi" ];
      };
    };
}
