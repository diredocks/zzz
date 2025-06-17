{
  description = "d3z";

  inputs.nixpkgs.url =  "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forEachSupportedSystem = f:
      nixpkgs.lib.genAttrs supportedSystems (system:
        f {
          pkgs = import nixpkgs {inherit system;};
        });
  in {
    devShells = forEachSupportedSystem ({pkgs}: {
      default =
        pkgs.mkShell.override
        {
          # Override stdenv in order to change compiler:
          # stdenv = pkgs.clangStdenv;
        }
        {
          shellHook = ''
            export SHELL=$(which zsh)
          '';
          packages = with pkgs;
            [
              libpcap
              # ^ of couse we need it
              pkg-config
              clang-tools
              cmake
              codespell
              cppcheck
            ]
            ++ (
              if system == "aarch64-darwin"
              then []
              else [gdb]
            );
        };
    });
  };
}
