{
  description = "Rotate GitHub PATs into environment secrets across multiple repositories";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "gh-pat-rotate";
          version = "0.1.0";

          src = ./.;

          vendorHash = "sha256-tCWrVkQJQ+AdMx5ZitcRgI/bAcpJQrNRJlPhjwNuyIQ="; # Will need to update this

          ldflags = [
            "-s"
            "-w"
          ];

          meta = with pkgs.lib; {
            description = "Rotate GitHub PATs into environment secrets across multiple repositories";
            homepage = "https://github.com/tcurdt/gh-pat-rotate";
            license = licenses.mit;
            maintainers = [ ];
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/gh-pat-rotate";
          meta = {
            description = "Rotate GitHub PATs into environment secrets across multiple repositories";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
          ];
        };
      }
    );
}
