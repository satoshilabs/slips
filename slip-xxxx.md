#SLIP-xxxx : Well Known Extended Purpose Codes for BIP-xxxx

```
Number:  SLIP-xxxx
Title:   Well Known Extended Purpose Codes for BIP-xxxx
Type:    Standard
Status:  Draft
Authors: ??Pavol Rusnak <stick@satoshilabs.com>??
         Ken Heutmaker <ken@keepkey.com>
Created: 2016-02-01
```

##Abstract

This is a list of well known extended purpose string for BIP-xxxx. Purpose
codes can be added to this list with a pull request that includes a new SLIP or
a reference to the relevant BIP that describes the purpose and the hierarchy of
the children nodes. Purpose codes on this list should be sorted by the encoded value.

##Motivation

BIP repository does not want to deal with assigning the values for various
coin types and HD wallet uses outside of Bitcoin so we propose this SLIP to become such body.

##Well Known Extended Purpose Codes

Purpose String | Encoded Value | Decoded Value | Short Description      | Details
---------------|---------------|---------------|------------------------|------------------------------
APIKEY         | d560cdde      | AP1KEY        | Deterministic API Keys | <SLIP-yyyy>

##References

- [BIP-xxxx: Extended Purpose Field for Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-xxxx.md)
