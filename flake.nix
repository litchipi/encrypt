{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-23.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    cargo2nix = {
      url = "github:cargo2nix/cargo2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
    flake-utils.follows = "cargo2nix/flake-utils";
  };

  outputs = inputs: with inputs;
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ cargo2nix.overlays.default ];
        };

        src = ./.;
        rustPkgs = pkgs.rustBuilder.makePackageSet {
          rustChannel = "stable";
          rustVersion = "1.70.0";
          packageFun = import ./Cargo.nix;
          extraRustComponents = [
            "clippy"
          ];
          workspaceSrc = src;
          packageOverrides = pkgs: pkgs.rustBuilder.overrides.all;
        };

      in {
        packages = {
          default = (rustPkgs.workspace.encryptf {}).bin;
        };
        devShells.default = rustPkgs.workspaceShell {
          RUST_BACKTRACE="full";
          CARGO_NET_GIT_FETCH_WITH_CLI = "true";
          SRC=src;
        };
      }
    );
}
