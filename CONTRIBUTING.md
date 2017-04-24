Make sure your changes are valid through both rustfmt and clippy.

# Installing Climate Tooling

1. In the project folder, make sure we're using the latest nightly:
```
rustup toolchain install nightly
rustup override set nightly
```

2. Install the tools we'll be using to work on the project, making sure we're using the latest versions:
```
cargo install --force clippy
cargo install --force rustfmt
```

