{
  inputs.nixpkgs.url = "github:NixOs/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }: let
    lib = nixpkgs.lib;

    supportedSystems = lib.platforms.unix;
    forSystem = f: system: f {
      inherit system;
      pkgs = import nixpkgs { inherit system; };
    };
    forAllSystems = f: lib.genAttrs supportedSystems (forSystem f);
  in {
    devShells = forAllSystems ({ system, pkgs, ... }: {
      default = pkgs.mkShell {
        name = "dev";

        buildInputs = with pkgs; [ go_1_22 gopls jq ];
	shellHook = ''
          export PS1="\033[0;36m[ ]\033[0m $PS1"
        '';
      };
    });
  };
}
