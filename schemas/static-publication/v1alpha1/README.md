# Static publication v1alpha1 schemas

These Draft 2020-12 schemas are the public snapshot of the M3 static-publication
contract. Every object is closed with `additionalProperties: false`, and the
host independently applies the semantic validators in `static_contracts` after
duplicate-member-safe JSON decoding.

`OperationRequest` is the only request document. `Site` is root-generated
desired state and is deliberately not a request or transport frame. The
byte-identical copies packaged with `lowerduckpond-static-contracts` let an
installed wheel validate without access to this repository; the test suite
fails if either copy drifts.
