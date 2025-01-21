# age-plugin-kms

Forked from jtdowney/age-kms-plugin, these were his notes:

> This project is a Kubernetes KMS v2 plugin using
> [age](https://age-encryption.org/). When I originally started this my goal was
> to use the Rust [age crate](https://crates.io/crates/age) which supports
> [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey), however I ran
> into trouble getting Kubernetes and Tonic (the Rust GRPC library) to agree on
> how to handle Unix Domain Sockets. I rewrote the plugin in Go and it works great
> except the age Go library doesn't support plugins yet. So now I am just
> abandoning this project. I am leaving it here in case anyone wants to use it as
> a reference for writing their plugin.
