{ compiler ? "default" }:

let
  rev = "a790b646e0634695782876f45d98f93c38ceae1d";
  url = "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
  pkgs = import (builtins.fetchTarball url) {};
  dontCheck = pkgs.haskell.lib.dontCheck;
  ignore =
  let
    owner = "hercules-ci";
    repo = "gitignore";
    rev = "c4662e662462e7bf3c2a968483478a665d00e717";
  in
    import (builtins.fetchTarball {
    url = "https://github.com/${owner}/${repo}/archive/${rev}.tar.gz";
    sha256 = "sha256:1npnx0h6bd0d7ql93ka7azhj40zgjp815fw2r6smg8ch9p7mzdlx";
  }) { inherit (pkgs) lib; };

  hPkgs = if compiler == "default"
              then pkgs.haskellPackages
              else pkgs.haskell.packages.${compiler};

  src = ignore.gitignoreSource ./.;
  lib = pkgs.haskell.lib;
  haskellPkgs = hPkgs.extend (self: super: {
    jose-jwt = lib.markUnbroken super.jose-jwt;
    broch = self.callCabal2nix "broch" src {};
  });
in
  {
    broch = haskellPkgs.broch;
  }
