{ config, lib, pkgs, ... }:

let
  cfg = config.envs.ssotGithubRefs;

  repoType = lib.types.submodule {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Bare repository name without the .git suffix.";
      };

      githubUrl = lib.mkOption {
        type = lib.types.str;
        description = "Read-side GitHub SSH URL.";
      };
    };
  };

  defaultRepoNames = [
    "adrs"
    "governance"
    "flakes"
    "ui"
    "envs"
    "ops"
  ];

  repairOwnerWrite = lib.optionalString cfg.repairOwnerWrite ''
    find "$gitdir" -type d -exec chmod u+w {} +
    if [ -f "$gitdir/config" ]; then
      chmod u+w "$gitdir/config"
    fi
  '';

  repoCommands = lib.concatMapStringsSep "\n" (repo: ''
    ensure_repo ${lib.escapeShellArg repo.name} ${lib.escapeShellArg repo.githubUrl}
  '') cfg.repositories;

  fetcher = pkgs.writeShellApplication {
    name = "envs-ssot-github-refs-fetch";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.findutils
      pkgs.git
      pkgs.openssh
    ];
    text = ''
      set -euo pipefail

      bare_root=${lib.escapeShellArg cfg.bareRoot}

      ensure_repo() {
        name="$1"
        url="$2"
        gitdir="$bare_root/$name.git"

        if [ ! -d "$gitdir" ]; then
          echo "SSOT_GITHUB_REFS_MISSING_REPO name=$name path=$gitdir" >&2
          return 1
        fi

        ${repairOwnerWrite}

        if git --git-dir="$gitdir" remote get-url github >/dev/null 2>&1; then
          git --git-dir="$gitdir" remote set-url github "$url"
        else
          git --git-dir="$gitdir" remote add github "$url"
        fi

        git --git-dir="$gitdir" config --replace-all remote.github.fetch \
          "+refs/heads/*:refs/remotes/github/*"
        git --git-dir="$gitdir" config --unset-all remote.github.pushurl \
          >/dev/null 2>&1 || true
        git --git-dir="$gitdir" remote set-url --push github DISABLED

        GIT_TERMINAL_PROMPT=0 git --git-dir="$gitdir" fetch --prune github
        git --git-dir="$gitdir" remote set-head github -a >/dev/null 2>&1 || true

        if git --git-dir="$gitdir" show-ref --verify --quiet refs/heads/proposals; then
          echo "SSOT_GITHUB_REFS_DRIFT name=$name ref=refs/heads/proposals" >&2
        fi

        for ref in refs/heads/main refs/remotes/github/main refs/remotes/github/proposals; do
          if git --git-dir="$gitdir" show-ref --verify --quiet "$ref"; then
            sha="$(git --git-dir="$gitdir" rev-parse "$ref")"
            echo "$name $ref $sha"
          else
            echo "$name $ref ABSENT"
          fi
        done
      }

      ${repoCommands}
    '';
  };
in
{
  options.envs.ssotGithubRefs = {
    enable = lib.mkEnableOption "GitHub remote-tracking refs for SSOT bare repositories";

    bareRoot = lib.mkOption {
      type = lib.types.str;
      default = "/home/nixos/repos/.bare";
      description = "Directory containing SSOT bare repositories.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "nixos";
      description = "User that owns and fetches the SSOT bare repositories.";
    };

    repairOwnerWrite = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Restore owner write permission on bare repo directories before fetch.";
    };

    interval = lib.mkOption {
      type = lib.types.str;
      default = "15min";
      description = "systemd OnUnitActiveSec interval for periodic fetch.";
    };

    repositories = lib.mkOption {
      type = lib.types.listOf repoType;
      default = map (name: {
        inherit name;
        githubUrl = "git@github.com:roccho-dev/${name}.git";
      }) defaultRepoNames;
      description = "Allowlisted SSOT repositories to observe from GitHub.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ fetcher ];

    systemd.services.envs-ssot-github-refs-fetch = {
      description = "Fetch GitHub refs into SSOT bare repositories";
      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
      };
      script = "${fetcher}/bin/envs-ssot-github-refs-fetch";
    };

    systemd.timers.envs-ssot-github-refs-fetch = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = cfg.interval;
        Unit = "envs-ssot-github-refs-fetch.service";
      };
    };
  };
}
