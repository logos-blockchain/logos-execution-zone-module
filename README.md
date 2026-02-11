# Logos Blockchain Module

### Setup

#### IDE

If you're using an IDE with CMake integration make sure it points to the same cmake directory as the `justfile`, which defaults to `build`.

This will reduce friction when working on the project.

#### Nix

* Use `nix flake update` to bring all nix context and packages
* Use `nix build` to build the package
* Use `nix run` to launch the module-viewer and check your module loads properly
* Use `nix develop` to setup your IDE
