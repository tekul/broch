{ compiler ? "default" }:

let
  pkgs = import <nixpkgs> {};
  dontCheck = pkgs.haskell.lib.dontCheck;
  hPkgs = if compiler == "default"
              then pkgs.haskellPackages
              else pkgs.haskell.packages.${compiler};

  haskellPkgs = hPkgs.extend (self: super: {
    broch = self.callPackage ./broch.nix {};
  });
in
  {
    broch = haskellPkgs.broch;
  }
