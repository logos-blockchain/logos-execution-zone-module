{
  description = "Logos Execution Zone Core Module";

  # Pull pre-built artifacts from the self-hosted Logos Attic cache(Nix binary cache).
  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [ "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU=" ];
  };

  inputs = {
    # Latest master commit
    logos-module-builder.url = "github:logos-co/logos-module-builder?rev=5f74cdb3cecacde054c68d72fcc0d2cfe2195900";
    # Latest main commit
    nix-bundle-lgx.url = "github:logos-co/nix-bundle-lgx?rev=e65d38263f2e1e6bca274d676684350b0fb54185";
    lez-rust-overlay.url = "github:oxalica/rust-overlay/b2ccad3b67335d368eef49ec48b9c8166858e73d";
    logos-execution-zone = {
      url = "github:logos-blockchain/logos-execution-zone?ref=v0.4.0-rc1";
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
