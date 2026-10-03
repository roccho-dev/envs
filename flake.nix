{
  description = "envs repo-owned effect toolchain";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/f9948418dc8628ac02b6d6337e191ade9429d59d";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      # Access probe: the cloudflared version windows PR #21 ships, and OpenTofu carrying only the standard Cloudflare
      # provider in its closure, so a run acquires nothing from a registry.
      cloudflared = assert pkgs.cloudflared.version == "2026.6.1"; pkgs.cloudflared;
      opentofu = pkgs.opentofu.withPlugins (p: [ p.cloudflare_cloudflare ]);
      # curl signs the state proof's scoped S3 object requests with the temporary credential (aws:amz:auto:s3).
      packages = with pkgs; [ python3 sops wrangler git gh openssh curl ] ++ [ cloudflared opentofu ];
      # The exact committed source this artifact is built from; a dirty tree cannot produce one.
      rev = self.rev or (throw "envs effect artifact requires a clean committed source");

      # The adapter compares this manifest with flake.lock and uses only these absolute tools.
      tools = {
        python3 = "${pkgs.python3}/bin/python3";
        sops = "${pkgs.sops}/bin/sops";
        wrangler = "${pkgs.wrangler}/bin/wrangler";
        git = "${pkgs.git}/bin/git";
        gh = "${pkgs.gh}/bin/gh";
        tofu = "${opentofu}/bin/tofu";
        cloudflared = "${cloudflared}/bin/cloudflared";
        ssh = "${pkgs.openssh}/bin/ssh";
        sshd = "${pkgs.openssh}/bin/sshd";
        ssh_keygen = "${pkgs.openssh}/bin/ssh-keygen";
        curl = "${pkgs.curl}/bin/curl";
      };
      manifest = pkgs.writeText "envs-effect-toolchain.json" (builtins.toJSON {
        kind = "envs.effectToolchain.v1";
        nixpkgs = { inherit (nixpkgs) rev narHash; };
        source = rev;
        inherit tools;
      });

      # Sole authoring/projection entry: the adapter from this exact source, with no ambient PATH.
      entry = pkgs.writeShellScriptBin "envs-effect" ''
        set -euo pipefail
        export PATH=${nixpkgs.lib.makeBinPath packages}
        export ENVS_EFFECT_TOOLCHAIN=${manifest}
        export SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
        exec ${tools.python3} -I ${self}/adapters/jev_api.py "$@"
      '';

      effect-toolchain = pkgs.buildEnv {
        name = "envs-effect-toolchain";
        paths = [ entry ] ++ packages;
      };

      # Provided artifact: the complete store closure plus ENTRY and SOURCE, deterministic so CI can hand it off by digest.
      effect-artifact = pkgs.runCommand "envs-effect.tar" {
        closure = pkgs.closureInfo { rootPaths = [ effect-toolchain ]; };
      } ''
        echo ${effect-toolchain}/bin/envs-effect > ENTRY
        echo ${rev} > SOURCE
        tar --create --file "$out" --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
          ENTRY SOURCE $(cat "$closure/store-paths")
      '';

      # Windows placement distribution (windows #14): the official Windows SOPS client of exactly the locked sops
      # version (its release asset digest, equal to its published checksums.txt), the entrance, the rent receiver and
      # this exact source's committed ciphertexts. It decrypts on the target; it holds no identity or credential.
      sops-windows = pkgs.fetchurl {
        url = "https://github.com/getsops/sops/releases/download/v${pkgs.sops.version}/sops-v${pkgs.sops.version}.amd64.exe";
        hash = assert pkgs.sops.version == "3.13.2"; "sha256-y2/sduI8tKxWdxrDhHKw/hunmoSb8iAK7afJRnoEW3s=";
      };
      # The official Windows age release archive; only its age-keygen.exe is shipped, so a target can create its own
      # identity in place and export only the public recipient. Its exact LICENSE ships alongside (LICENSES/).
      age-windows = pkgs.fetchurl {
        url = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-windows-amd64.zip";
        hash = "sha256-9I2Pj56+kDq1An7QZ2UvLMHblLwgaXZDATO5BdzY6Mc=";
      };
      placement-artifact = pkgs.runCommand "envs-placement" { nativeBuildInputs = [ pkgs.unzip ]; } ''
        mkdir -p "$out" "$out/LICENSES"
        cp ${self}/adapters/place.ps1 ${self}/adapters/rent-receive.sh "$out/"
        cp ${sops-windows} "$out/sops.exe"
        unzip -p ${age-windows} age/age-keygen.exe > "$out/age-keygen.exe"
        # The committed license texts are exactly the ones these binaries come with.
        unzip -p ${age-windows} age/LICENSE | cmp - ${self}/LICENSES/age-v1.3.2.txt
        cmp ${pkgs.sops.src}/LICENSE ${self}/LICENSES/sops-v3.13.2.txt
        cp ${self}/LICENSES/age-v1.3.2.txt ${self}/LICENSES/sops-v3.13.2.txt "$out/LICENSES/"
        cp ${self}/THIRD_PARTY_NOTICES.md "$out/"
        echo ${rev} > "$out/SOURCE"
        if [ -d ${self}/ciphertexts ]; then cp -r ${self}/ciphertexts "$out/ciphertexts"; fi
      '';
    in
    {
      packages.${system} = {
        inherit effect-toolchain effect-artifact placement-artifact;
        default = effect-toolchain;
        # Check-only: a throwaway identity for the real SOPS roundtrip; never in the effect toolchain or artifact.
        check-age = pkgs.age;
      };
    };
}
