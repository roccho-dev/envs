{
  description = "Exact DuckDB package bindings for OS and user scopes";

  inputs = {
    nixpkgs.url = "nixpkgs/f9948418dc8628ac02b6d6337e191ade9429d59d";
    packagePrimitives = {
      type = "indirect";
      id = "flakes-duckdb-cli";
      rev = "b369525b9d1ca998b7fc9ebeeec4517a6f167558";
      dir = "published/duckdb-cli";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, packagePrimitives }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      bindingLib = import ../../lib/package-bindings.nix;
      inherit (bindingLib) mkPackageRef mkPackageBinding;

      revision = "b369525b9d1ca998b7fc9ebeeec4517a6f167558";
      subflake = "published/duckdb-cli";
      output = "packages.${system}.duckdb-cli";
      primitive = packagePrimitives.packages.${system}.duckdb-cli;
      identity = primitive.passthru.packagePrimitive;
      packageRef = mkPackageRef {
        producer = "flakes";
        inherit revision subflake output;
        primitive = identity;
      };
      osDuckdbCli = mkPackageBinding {
        scope = "os";
        inherit packageRef;
        package = primitive;
      };
      userDuckdbCli = mkPackageBinding {
        scope = "user";
        inherit packageRef;
        package = primitive;
      };
      contract =
        assert (packagePrimitives.rev or "") == revision;
        assert identity.kind == "flakes.packagePrimitive.v1";
        assert identity.id == "duckdb-cli";
        assert identity.version == "1.5.4";
        assert identity.mainProgram == "duckdb";
        assert osDuckdbCli.scope == "os";
        assert userDuckdbCli.scope == "user";
        assert osDuckdbCli.packageRef == userDuckdbCli.packageRef;
        assert osDuckdbCli.package.outPath == userDuckdbCli.package.outPath;
        true;
    in
    assert contract;
    {
      lib = {
        inherit packageRef;
        packageBindings = {
          os-duckdb-cli = osDuckdbCli;
          user-duckdb-cli = userDuckdbCli;
        };
      };

      packages.${system} = {
        os-duckdb-cli = osDuckdbCli.package;
        user-duckdb-cli = userDuckdbCli.package;
      };

      checks.${system}.binding-contract = pkgs.runCommand "duckdb-os-user-binding-contract" { } ''
        set -eu
        test -x ${primitive}/bin/duckdb
        ${primitive}/bin/duckdb --version > "$TMPDIR/duckdb-version"
        grep -Eq '(^|[^0-9])1[.]5[.]4([^0-9]|$)' "$TMPDIR/duckdb-version"
        touch "$out"
      '';
    };
}
