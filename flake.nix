{
  description = "NixOS environment modules and provider-neutral package bindings";

  inputs.nixpkgs.url = "nixpkgs/f9948418dc8628ac02b6d6337e191ade9429d59d";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      packageBindings = import ./lib/package-bindings.nix;
      inherit (packageBindings)
        mkPackageRef
        mkPackageBinding
        mkInstalledPackageBindingReceipt
        mkNixosUserPackageModule
        ;

      codexPackageRef = mkPackageRef {
        producer = "flakes";
        revision = "3d3b2826bd1470189dcfaa810a574a7d0c071251";
        subflake = null;
        output = "packages.${system}.codex-cli";
        primitive = {
          kind = "flakes.packagePrimitive.v1";
          id = "codex-cli";
          version = "0.144.1";
          mainProgram = "codex";
          target = "x86_64-unknown-linux-musl";
          layout = "openai.codexPackage.v1";
        };
      };
      mkCodexUserBinding = { package }: mkPackageBinding {
        scope = "user";
        packageRef = codexPackageRef;
        inherit package;
      };
      mkNixosVmCodexModule = { package }: mkNixosUserPackageModule {
        user = "nixos";
        binding = mkCodexUserBinding { inherit package; };
      };

      codexContractFixture = pkgs.runCommand "codex-cli-contract-fixture-0.144.1" {
        passthru.packagePrimitive = codexPackageRef.primitive;
      } ''
        set -eu
        mkdir -p "$out/bin"
        cat > "$out/bin/codex" <<'EOF'
        #!${pkgs.runtimeShell}
        case "''${1:-}" in
          --version)
            printf 'codex-cli 0.144.1\n'
            ;;
          app-server)
            test "''${2:-}" = "--help"
            printf 'Codex app-server contract fixture\n'
            ;;
          *)
            exit 64
            ;;
        esac
        EOF
        chmod +x "$out/bin/codex"
      '';
      codexContractBinding = mkCodexUserBinding { package = codexContractFixture; };
      codexContractModule = mkNixosVmCodexModule { package = codexContractFixture; };
      codexContractReceipt = mkInstalledPackageBindingReceipt {
        user = "nixos";
        binding = codexContractBinding;
      };
      codexModuleEvaluation = nixpkgs.lib.evalModules {
        modules = [
          ({ lib, ... }: {
            options.users.users = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule ({ lib, ... }: {
                options.packages = lib.mkOption {
                  type = lib.types.listOf lib.types.package;
                  default = [ ];
                };
              }));
              default = { };
            };
            options.environment.etc = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule ({ lib, ... }: {
                options.text = lib.mkOption { type = lib.types.str; };
              }));
              default = { };
            };
          })
          codexContractModule
        ];
      };
      codexContractCheck =
        assert codexPackageRef.producer == "flakes";
        assert codexContractBinding.kind == "envs.packageBinding.v1";
        assert codexContractBinding.scope == "user";
        assert codexContractBinding.packageRef == codexPackageRef;
        assert (builtins.head codexModuleEvaluation.config.users.users.nixos.packages).outPath == codexContractFixture.outPath;
        assert codexModuleEvaluation.config.environment.etc."envs/package-bindings/nixos/codex-cli.json".text == builtins.toJSON codexContractReceipt;
        assert codexContractReceipt.kind == "envs.installedPackageBinding.v1";
        assert codexContractReceipt.user == "nixos";
        assert codexContractReceipt.packageRef == codexPackageRef;
        assert codexContractReceipt.packageOutPath == codexContractFixture.outPath;
        true;
    in
    assert codexContractCheck;
    {
      lib = packageBindings // {
        inherit mkCodexUserBinding mkNixosVmCodexModule;
        packageRefs.codex-cli = codexPackageRef;
      };

      checks.${system}.codex-user-binding-contract = pkgs.runCommand "codex-user-binding-contract" { } ''
        set -eu
        test "$(${codexContractFixture}/bin/codex --version)" = "codex-cli 0.144.1"
        ${codexContractFixture}/bin/codex app-server --help > "$TMPDIR/app-server-help"
        test -s "$TMPDIR/app-server-help"
        test "${codexContractReceipt.packageOutPath}" = "${codexContractFixture.outPath}"
        touch "$out"
      '';

      nixosModules.default = self.nixosModules.ssot-github-refs;
      nixosModules.ssot-github-refs = import ./modules/ssot-github-refs.nix;
    };
}
