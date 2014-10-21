let
pkgs = import <nixpkgs> {};
  haskellPackages = pkgs.haskellPackages.override {
    extension = self: super: {
      broch = self.callPackage ./. {};
      joseJwt = self.callPackage ../jose-jwt {};
      bcrypt = self.callPackage ../nix-custom/bcrypt/0.0.5.nix {};
      dataDefaultGenerics = self.callPackage ../nix-custom/dataDefaultGenerics/0.3.nix {};
      mtl = self.callPackage ../nix-custom/mtl/2.1.3.1.nix {};
    };
  };

in
pkgs.lib.overrideDerivation haskellPackages.broch (attrs: {
  buildInputs = [ haskellPackages.cabalInstall ] ++ attrs.buildInputs;

  shellHook =
    ''
      alias ghci='ghci -XOverloadedStrings -hide-package network-2.5.0.0 -hide-package crypto-api'
    '';
})

