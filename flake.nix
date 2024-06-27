{
  inputs.nixpkgs.url = "github:NixOs/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: let
    lib = nixpkgs.lib;

    forSystem = f: system: f {
      inherit system;
      pkgs = import nixpkgs { inherit system; };
    };

    supportedSystems = lib.platforms.unix;
    forAllSystems = f: lib.genAttrs supportedSystems (forSystem f);
  in {
    devShells = forAllSystems ({ system, pkgs, ... }: {
      default = pkgs.mkShell {
        name = "dev";

        buildInputs = with pkgs; [
          go
          gopls

          jq
          sqlite

          libbpf
          ccls
          clang
          libllvm
        ];
	shellHook = ''
          export PS1="\033[0;36m[ ]\033[0m $PS1"
          # stop littering eBPF C programs with go:build ignore
          export CGO_ENABLED=0
        '';
      };
    });
  };
}
