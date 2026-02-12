{ pkgs, lib, config, ... }:

{
  languages.go.enable = true;

  packages = with pkgs; [
    gotools
    golangci-lint
    delve
    git
    gcc
  ];

  env = {
    GOPATH = "${config.env.DEVENV_STATE}/go";
    GOCACHE = "${config.env.DEVENV_STATE}/go-cache";
    GOMODCACHE = "${config.env.DEVENV_STATE}/go-mod-cache";

  };

  services.redis.enable = true;

  git-hooks.hooks = {
    gofmt.enable = true;
    govet.enable = true;
    golangci-lint.enable = true;
  };
}
