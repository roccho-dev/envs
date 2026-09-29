{
  description = "envs repo-owned effect toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/f9948418dc8628ac02b6d6337e191ade9429d59d";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      packages = with pkgs; [ python3 sops wrangler git gh ];

      # The adapter compares this manifest with flake.lock and uses only these absolute tools.
      tools = {
        python3 = "${pkgs.python3}/bin/python3";
        sops = "${pkgs.sops}/bin/sops";
        wrangler = "${pkgs.wrangler}/bin/wrangler";
        git = "${pkgs.git}/bin/git";
        gh = "${pkgs.gh}/bin/gh";
      };
      manifest = pkgs.writeText "envs-effect-toolchain.json" (builtins.toJSON {
        kind = "envs.effectToolchain.v1";
        nixpkgs = { inherit (nixpkgs) rev narHash; };
        inherit tools;
      });

      # Sole authoring/projection entry: the adapter from this exact source, with no ambient PATH.
      entry = pkgs.writeShellScriptBin "envs-effect" ''
        set -euo pipefail
        export PATH=${nixpkgs.lib.makeBinPath packages}
        export ENVS_EFFECT_TOOLCHAIN=${manifest}
        exec ${tools.python3} -I ${self}/adapters/jev_api.py "$@"
      '';

      effect-toolchain = pkgs.buildEnv {
        name = "envs-effect-toolchain";
        paths = [ entry ] ++ packages;
      };

      # Provided artifact: the complete store closure plus ENTRY, deterministic so CI can hand it off by digest.
      effect-artifact = pkgs.runCommand "envs-effect.tar" {
        closure = pkgs.closureInfo { rootPaths = [ effect-toolchain ]; };
      } ''
        echo ${effect-toolchain}/bin/envs-effect > ENTRY
        tar --create --file "$out" --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
          ENTRY $(cat "$closure/store-paths")
      '';
    in
    {
      packages.${system} = {
        inherit effect-toolchain effect-artifact;
        default = effect-toolchain;
      };
    };
}
