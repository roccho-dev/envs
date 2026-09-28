let
  mkPackageRef = { producer, revision, subflake ? null, output, primitive }:
    assert producer != "";
    assert revision != "";
    assert output != "";
    {
      kind = "envs.packageRef.v1";
      inherit producer revision subflake output primitive;
    };

  mkPackageBinding = { scope, packageRef, package }:
    assert builtins.elem scope [ "os" "user" ];
    assert packageRef.kind == "envs.packageRef.v1";
    assert package.passthru.packagePrimitive == packageRef.primitive;
    {
      kind = "envs.packageBinding.v1";
      inherit scope packageRef package;
    };

  mkInstalledPackageBindingReceipt = { user, binding }:
    assert user != "";
    assert binding.kind == "envs.packageBinding.v1";
    assert binding.scope == "user";
    {
      kind = "envs.installedPackageBinding.v1";
      inherit user;
      scope = binding.scope;
      packageRef = binding.packageRef;
      packageOutPath = binding.package.outPath;
    };

  mkNixosUserPackageModule = { user, binding }:
    let
      primitive = binding.packageRef.primitive;
      receiptPath = "envs/package-bindings/${user}/${primitive.id}.json";
      receipt = mkInstalledPackageBindingReceipt { inherit user binding; };
    in
    { ... }: {
      users.users.${user}.packages = [ binding.package ];
      environment.etc.${receiptPath}.text = builtins.toJSON receipt;
    };
in {
  inherit
    mkPackageRef
    mkPackageBinding
    mkInstalledPackageBindingReceipt
    mkNixosUserPackageModule
    ;
}
