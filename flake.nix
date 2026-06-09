{
  description = "Logos Execution Zone Wallet Module - Qt6 Plugin";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    nix-bundle-lgx.url = "github:logos-co/nix-bundle-lgx";
    logos-execution-zone.url = "github:logos-blockchain/lssa?rev=a3ed22288759961a2cabd74cbf1bd5f9319ec6af"; # latest functionality
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
    };
}
