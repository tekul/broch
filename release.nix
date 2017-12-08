{ compiler ? "ghc822" }:

let
  pkgs = import <nixpkgs> {};
  dontCheck = pkgs.haskell.lib.dontCheck;
  haskellPkgs = pkgs.haskell.packages."${compiler}".extend (self: super: {
    broch = self.callPackage ./broch.nix {};
  });
in
  {
    broch = haskellPkgs.broch;
  }
