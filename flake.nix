{
  description = "Logos Execution Zone Core Module";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    nix-bundle-lgx.url = "github:logos-co/nix-bundle-lgx";
    lez-rust-overlay.url = "github:oxalica/rust-overlay/b2ccad3b67335d368eef49ec48b9c8166858e73d";
    logos-execution-zone = {
      url = "github:logos-blockchain/logos-execution-zone?rev=80a648a155e524cf869b62778871b95cd6ac36a3";
      inputs.rust-overlay.follows = "lez-rust-overlay";
    };
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
