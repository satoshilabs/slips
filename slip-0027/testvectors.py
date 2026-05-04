#!/usr/bin/env python3
"""Generates the SLIP 27 test vectors (vectors.json).

The input values need only the Python standard library. The public key hashes
additionally need:

    pip install dilithium-py kyber-py slh-dsa

Public key hashes are generated for ML-DSA, ML-KEM and SLH-DSA. They are
omitted for XMSS, XMSS^MT and LMS.

Usage:

    python3 testvectors.py > vectors.json
"""

import hashlib
import hmac
import itertools
import json
import re

# BIP 39 seed of the mnemonic "all all all all all all all all all all all all"
# with an empty passphrase. Also the master secret of the SLIP 21 test vectors.
MASTER_SECRET = bytes.fromhex(
    "c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f"
    "74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8"
)

# Scheme registry: scheme label with braces, input labels, lengths in bytes.
REGISTRY = [
    ("ML-DSA-{44,65,87}", ["seed"], [32]),
    ("ML-KEM-{512,768,1024}", ["d", "z"], [32, 32]),
    ("SLH-DSA-{SHA2,SHAKE}-128{s,f}", ["SK.seed", "SK.prf", "PK.seed"], [16] * 3),
    ("SLH-DSA-{SHA2,SHAKE}-192{s,f}", ["SK.seed", "SK.prf", "PK.seed"], [24] * 3),
    ("SLH-DSA-{SHA2,SHAKE}-256{s,f}", ["SK.seed", "SK.prf", "PK.seed"], [32] * 3),
    ("XMSS-{SHA2,SHAKE256}_{10,16,20}_256", ["S_XMSS", "SK_PRF", "SEED"], [32] * 3),
    ("XMSS-{SHA2,SHAKE256}_{10,16,20}_192", ["S_XMSS", "SK_PRF", "SEED"], [24] * 3),
    (
        "XMSSMT-{SHA2,SHAKE256}_{20/2,20/4,40/2,40/4,40/8,60/3,60/6,60/12}_256",
        ["S_XMSS", "SK_PRF", "SEED"],
        [32] * 3,
    ),
    (
        "XMSSMT-{SHA2,SHAKE256}_{20/2,20/4,40/2,40/4,40/8,60/3,60/6,60/12}_192",
        ["S_XMSS", "SK_PRF", "SEED"],
        [24] * 3,
    ),
    ("LMS_{SHA256,SHAKE}_M32_H{5,10,15,20,25}_W{1,2,4,8}", ["I", "SEED"], [16, 32]),
    ("LMS_{SHA256,SHAKE}_M24_H{5,10,15,20,25}_W{1,2,4,8}", ["I", "SEED"], [16, 24]),
]


def expand_braces(label):
    """Returns the scheme labels described by a scheme label with braces."""
    parts = re.split(r"\{([^}]*)\}", label)
    fixed, choices = parts[0::2], [p.split(",") for p in parts[1::2]]
    for choice in itertools.product(*choices):
        yield "".join(a + b for a, b in zip(fixed, choice + ("",)))


SCHEMES = {
    scheme: (input_labels, lengths)
    for label, input_labels, lengths in REGISTRY
    for scheme in expand_braces(label)
}


# SLIP 21


def master_node(master_secret):
    return hmac.new(b"Symmetric key seed", master_secret, hashlib.sha512).digest()


def child_node(node, label):
    return hmac.new(node[:32], b"\x00" + label.encode("ascii"), hashlib.sha512).digest()


def key(node):
    return node[32:]


def node_at(path):
    node = master_node(MASTER_SECRET)
    for label in path:
        node = child_node(node, label)
    return node


# SLIP 27


def input_values(path, scheme):
    """Derives the input values of the key pair at the given path."""
    assert path.count(scheme) == 1
    input_labels, lengths = SCHEMES[scheme]
    return {
        label: key(node_at(path + [label]))[:length]
        for label, length in zip(input_labels, lengths)
    }


# Key generation of the schemes


def public_key(scheme, values):
    """Returns the public key generated from the input values, or None."""
    if scheme.startswith("ML-DSA-"):
        from dilithium_py import ml_dsa

        pk, _ = getattr(ml_dsa, scheme.replace("-", "_")).key_derive(values["seed"])
        return pk
    if scheme.startswith("ML-KEM-"):
        from kyber_py import ml_kem

        ek, _ = getattr(ml_kem, scheme.replace("-", "_")).key_derive(
            values["d"] + values["z"]
        )
        return ek
    if scheme.startswith("SLH-DSA-"):
        import slhdsa
        from slhdsa.lowlevel.addresses import Address
        from slhdsa.lowlevel.xmss import XMSS

        par = getattr(slhdsa, scheme[len("SLH-DSA-") :].lower().replace("-", "_"))
        pk_root = XMSS(par).node(
            values["SK.seed"], 0, par.h_m, values["PK.seed"], Address(par.d - 1, 0)
        )
        return values["PK.seed"] + pk_root
    return None


def vector(description, path, scheme):
    values = input_values(path, scheme)
    result = {
        "description": description,
        "path": path,
        "scheme": scheme,
        "input_values": {label: value.hex() for label, value in values.items()},
    }
    pk = public_key(scheme, values)
    if pk is not None:
        result["public_key_hash"] = hashlib.sha256(pk).hexdigest()
    return result


def vectors():
    # The example paths of the specification.
    yield vector(
        "Example: account-based chain",
        ["SLIP-9999", "60", "2", "ML-DSA-44"],
        "ML-DSA-44",
    )
    yield vector(
        "Example: UTXO-based chain",
        ["SLIP-9999", "0", "2", "p2mr", "SLH-DSA-SHAKE-128s", "1", "14"],
        "SLH-DSA-SHAKE-128s",
    )

    # Handling of paths.
    yield vector(
        "Scheme label directly below the application label",
        ["SLIP-9999", "ML-KEM-768", "0"],
        "ML-KEM-768",
    )
    yield vector(
        "No key pair labels",
        ["SLIP-9999", "0", "2", "p2mr", "1", "14", "ML-DSA-65"],
        "ML-DSA-65",
    )
    yield vector(
        "Integer labels 0 and 2147483648",
        ["SLIP-9999", "0", "ML-DSA-44", "2147483648"],
        "ML-DSA-44",
    )
    yield vector(
        "Context label and key pair label equal to an input label",
        ["SLIP-9999", "seed", "ML-DSA-44", "seed"],
        "ML-DSA-44",
    )

    # Every scheme in the registry.
    for scheme in SCHEMES:
        yield vector(scheme, ["SLIP-9999", "0", scheme], scheme)


if __name__ == "__main__":
    print(json.dumps(list(vectors()), indent=2))
