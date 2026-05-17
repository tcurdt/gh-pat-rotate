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
          version = "0.2.0";

          src = ./.;

          vendorHash = "sha256-RjaUVht62RTlw5/TYSws9HY5arfqXejzN9uupcw593U=";

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
