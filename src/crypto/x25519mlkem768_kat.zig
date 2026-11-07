// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Known-answer tests for the TLS 1.3 X25519MLKEM768 hybrid group (0x11ec,
//! draft-ietf-tls-ecdhe-mlkem): key_share layouts and the combined (EC)DHE
//! secret `ML-KEM ss || X25519 ss` that `tls_client.zig` / `tls_server.zig`
//! feed to the key schedule.
//!
//! Provenance: draft-ietf-tls-ecdhe-mlkem-05 (checked 2026-11-07) publishes no
//! test vectors, so these are cross-implementation vectors derived with
//! OpenSSL 3.5.9 (libcrypto; independent of Zig std). The client vector uses
//! OpenSSL's own `X25519MLKEM768` hybrid KEM provider (`EVP_PKEY_fromdata` of
//! the client share, then `EVP_PKEY_encapsulate`); OpenSSL's component ML-KEM
//! decap + X25519 derive were checked to give exactly `mlkem_ss || x25519_ss`.
//! The server vector uses OpenSSL ML-KEM-768 encapsulation with the FIPS 203
//! `m` input fixed via the `ikme` parameter, plus OpenSSL X25519. Inputs:
//! ML-KEM-768 keygen seed `d || z` and raw X25519 secret keys, as below.
//!
//! The steps here repeat, on the same primitives, the inline hybrid code in
//! `tls_client.zig` (`HybridKx.generateDeterministic`, share = `ek ||
//! x25519_pk`; decap = `mlkem.decaps(ct) || X25519(sk, pk)`) and
//! `tls_server.zig` (encaps against the client `ek`, share = `ct ||
//! x25519_pk`). They pin the primitives and the byte ordering against an
//! independent implementation; they do not drive the TLS engines themselves
//! (the server draws its ML-KEM randomness from the OS, so it has no
//! deterministic seam).
const std = @import("std");
const kx = @import("kx.zig");

const MlKem = kx.HybridKx.MlKem;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const client_x25519_sk = hex("212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4");
const client_mlkem_seed = hex("10171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9");
/// ClientHello key_share: ML-KEM-768 ek (1184) || X25519 public key (32).
const client_share = hex("f0803999ba9f5ae28c944492f7a38492a73d71d667cfc7334f69cd26b39dae523a5ed73b169305ce97b01cc34fbff73dbab5b86bdabc24f182b4983be014bd00" ++ "5a445d5c58f0e5702892792d3c7bacd5702dec34f036867766b9c348857bfa539519a529848e89662672a2130493bf1309c339e06744ac4fe49aacbfe0c1c43a" ++ "6e10494bb6ba3f0895b7a73ca583506706e4a800e1465eecb65813a4fdfb429d00c25b005306313a2dc427154440eb815b61d3abad7816476c14eb929985e732" ++ "6dcc8c277350bc4010b24ac29b299b6c5bca2e44273c206788f9ae14d6abee7b09c22cc6368a3dadd34f3348a65e95a8911a41d82a12b2554291bb43abc7599c" ++ "3c731061598ce830d0c10637f88639767785daa583fb81fcf626b916c76451b991326540206836550b1991bc5ad11174032390b48743e44c1e8343d380c77a17" ++ "0279d793167539d59b03fb769b9924b9fbd2023321b2eb57ac952a6761bc5e3b558d0200cb8a750e1c8282ebb8ba6d4180e730af4c10c023c5369dfa12c75607" ++ "4f095e907acad84a43b894733e12844fd531af358142f6a600b87fbb593f3fac251ca52c10cc385faa23cafcbc77e94eb848236992c8d64c331dac802652a779" ++ "361b6567312f1993ca64b1d00477f5ec44e152c08cf8b6eed8c1680361bc564e04d2b15cd97a975a67b89b2613616cfe131de9b5b3f8db3c2fea63c33bae14f0" ++ "3c3d1790bf004c666723668a03a1e05a01f51362090484090e60989c37ea10fe42c0953b45380891078a14c8e857b13a9808f6c8648b12b792347a360ba9a818" ++ "c11645ed23c2b3b6592bd3a0c6858a8914ccbff65898e043911ba4c3f4665103abbaec9a58bc94a6e895547094007c98cdcb6f1b6237d3b93c3a66b5d2246a58" ++ "b91b71c84073b47583e582c5599d8765974e1564ee820810c017461b4a4571c881aab0710199fbc1673161b9091c598c19937a400584aa4c9b4408e3e5314060" ++ "b60052b0ca659b7f791e9d7777bffb5addf66c4c078b8320bf1f255d1e77cf881000d8a707c8bb61e63b24bacbb231cb2e62b34794523bda37166b952f096257" ++ "e0f22b0407adfb560e047088009a4b9ff33a9b6b23530429fbf402ec650e0bc73b8269622c974708bc047a015e8c1a258ff5958ca99199dcaafab87d3b66aff6" ++ "d45019d59f2729997b757fda88b7649a8a63d73ddf622715e14578c5520a246051f6369880009eea77640ac877469d045743dd1a39269c6f431b81eb14854b36" ++ "3501296556406ccd426c1f761daac8626c238a5fec41acba2a18176f6d453e7710174345a5f31b4755c6569e50896041bf74f23d3aa9757f6503ede66cf46049" ++ "f6924905900341e79a1d880db8fa3d557bbfcc57a725b0627ac0813d709ba2321baa59223cf8733393c2225bbb02863b73023d6d130101c17bf494cb9a91af4c" ++ "a9b40fdb1f1d2a0d2cb9c33590a0a82413c8f73caf14ce439a96c550caf8163b2490c510ca86ad266e7edac29053ac5678878956aadb91050bec1d7395316fe9" ++ "3f73e7cae2b0125519c99b724c9126945db434dee7cd6eb640922403c24c513109aa0cd661a72379b0582f82b60261d82ec7730433a392a586590eb760314808" ++ "e7b55ca647437641d62e7b81f1174ca72ed2c81a01684f3bfa9e9724797e4ec27edd358df352a24d6934c671d268024fba2ff13259d70917fe360c751f30695a");

/// OpenSSL hybrid encapsulation against `client_share`.
const openssl_server_share = hex("cc3d0928d9a329dbcaa6721423948dbb32203fe106008fc0db7a55124e34c6b13c28d764608eb19300cd2dcfd4281ac5a71d1f6aeaf471183686bb74391635d3" ++ "48336bd1bff4c801471a2e1f17ff4315d55a62bfbe0af143d0225f83dd47655e6f6bd12b49426ee2882d9dcb8689616301e7ada702d7379fd48e50479e850068" ++ "f637f105b9ba1d86b93a04d260e078d09c2e9f37cef31d00be29a07b6637056c86ac8c8fd0d686d273d63f137073fc47fe459285a660a27dfe9bfad2bc89060a" ++ "07037701398d986f425ac7a20ca5c279dd0f6b2b013485117ae8b37af84c920f47a7e076b1a84c8fbdfbf5ca007f8b011404b5795f7e25cb4b135b1d993c8b33" ++ "ee60b110b2f88f836554679d76f5bb33f786fc3b5ca6e730f78ce56b956a04113107983a35a443ab1a7f86f34d21c9fcb67ac163334f2d7987257f3e2a3d27d9" ++ "ac5a13dc8acc4f345b520775465c52bbbd43e97941c188b671058dfdfd632a3736ef9d969f042acb3cc4f5bce3a1099f3ad0a2cbe27c7c61b93e4144d69b7021" ++ "10f8b14ec26d75a9f196ddadb5db223effa1d3bf3f44f6ad56b1181ac5658998ff50812cb9235c26651ea1b64f3d7d245dd5a71ade1e44f0bb214a63aada3122" ++ "07ff6b8de526de8aeced2370ed05c65588e50a88d02a2da06d7d4f58b21f5e971dfe8b3a6d414d509717b19b21bb4a119d6520ae5ec0f56ae50e97b535164366" ++ "46f958a6144717b213afa4f05b349c7648071fd13c7011b9043cf1d06b6b48dfc00621b97bc0c44464218986090f4d4a8df39e68c9348ecd6037c710de92fde9" ++ "b1cc3b65f844ef9844ff6f87061f34802bba54009ba0168ac49545c80a143c699e81eae23a4861b0503f3a7a2ce8a6fef6a9791eed37aa03aa43b5beff17ee79" ++ "70beb2eb8d283986dd010d4ef25d9313a2696b9b37f973f9e675d2c55203bd427a4b95c2bfdf9c013ba6b4b764889b8b05f7798cb1124daeabc0a4e59ae8260d" ++ "1761c1f2484bbe66c2f452c190068eb9415dcfb08b818357dd63982f6fe6deb4d4c45737421f6dbb16a86a0c3f09a1bfdfc14b75b7b329cdbe2ed97a236a6e67" ++ "f94b53bdcc644708c1a7a6007f4f44960e6e561cc45374492cb02ed348d8720ff27a8f84e16657392b1e01ae3eb3ecc593537db4c26c3faaca1e86e1dec99911" ++ "a188f1bd1942a64e049e16a24506cb63e1d0a329805723fda140c594aa7a1b66a865278615de7c8bddabeb25ac42eea5d3e2555118d53a6bea159f488e8687a7" ++ "db5524b3a1b9f2d90d270533c06b7849f4e09d37c86f1bdb1eb017140ed1658fa0f15df8771576d50834ced56e3ad51a4bafeba70535bce0f38daea826325faf" ++ "1d03f54b10d3100094d6c4848b283beaca84cc9d56ad7c04834fcce431baf30f449a704a17aa03814ffe42bdd8f115162326e539f5fe6a69bfd7e1ee0595077c" ++ "92dc4666ac59c1c33a2b051619609d6d5e606ad796e3494451ebc7aeb79e4922608c07dc3e6395eda41a8c0e579dda788c1739c70c0035c26d1a4813f827504c" ++ "c4d64e63c758dcd1b1d268230d53d7666b193e41b11ff558c05079adbc0ae075");
const openssl_shared_secret = hex("f9786d7bc97fd04e9b4391ff079694dbb68e39f231e65a519bcdb1797906678c05aabd718bb569a37303bec2a2c976a9239cdca69ff371cd43d44e2bca3ece4e");

/// Deterministic server side: ML-KEM `m` (ikme) and the server X25519 secret.
const server_ikme = hex("33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ce");
const server_x25519_sk = hex("c0c3c6c9cccfd2d5d8dbdee1e4e7eaedf0f3f6f9fcff0205080b0e1114171a1d");
const server_share = hex("aeb67ba431f884a578f78c84aa64e7c64be0cb9a48bc59bbf2f8e5472e38c0bef4ac288f1c245251a849d189c9c77639ab07705da180de66c7ebfefac33c7809" ++ "429e9c4d0bee9eaf2b7258690789e2e26d7eb3f2bdc57cd21a1672e9959edb3105ea0c902f87fc62c20b87053ad3bd18a53e2a1e541ed14665c1f6a8fe95d059" ++ "23795e433e04d0054b1d6b42e03e13806efd3bef453f291ab9af433ec93b33ac1866ad2478f68e2cc533b2a36dde2b5d5ea2237c84b7b493c8ca09a546bace38" ++ "c6726a5f587d2975912c2d7d67b87cca932cb899133afada552ffa75652926807be9b15b8c5efd644d8eff1f4b0aef1e44daf6f44f8c4288a1e0caa4323551f9" ++ "b83710c2b71edbb9ffc15ec78904d7624d208abfdffcda6d47efaa6597f564657b514668b0a19d1b9b9428c0c984cc99fa21856f0d878bac0f553808b3f97cb7" ++ "8a639fb2d93445f42173b97cc41281ec3ed8f0817dc0daa356103c26111e338bcdedc1c7491d9b2530969e52f0d35081ce22f36262227620e6d40eff6b136d24" ++ "e368b123490414d7c4ed74c5c8a3185849232dff5804c681f75ff8183e2b9867b472d2f94d5d6afc57ead5f62a791cd27987dfe766865aa8709801e3bb6c928f" ++ "ca038ec5d465cde9851928124ea019dd0f4692aacb78cb7dbc167e6cae388afbfc9deb28f6893e8f5f75af127a8ad443311c7fe9febd1d0b3d23eb78e9d0ddeb" ++ "de9b7422a7cf42b2293f902b9772cd3e44fd32beb6c2cc63acd34bb20b133e8c2db711f054e05c65202af7009254ca46031e1f4d35bb4f0211aa84b199d88818" ++ "56e0bd872a4c57c2a6be6bc34caa05fefa64594d6bf631e62e607cd31c56bdfad7797c76183d92b4c20ca7442d21c77a3e51f069b09b51c988e6c45fa3bd731f" ++ "3a43f0b60dbc242faa32671a7b6e418c4d9c809c2fe56c928e9195c1757828d7839aa650273d254f780b37a3b487afabc8ce03a72f1f33be63b9a8ea4aecea02" ++ "b8aa2f4e32148ce7854c899d0da90dcc56308ddda9bd2d3e8702ad161e18d1d0617bd46494bdc9042a1e88d99cfd626366c85f673b1094fa44f0668ec85624c3" ++ "442c290d40422c93478b024ab929a7df572464a36ced244a85ecc62cf6c450fbb905b82557a6119ed194df8b1517da7edefa4840f24b5de2a40b7437e66095b2" ++ "a72784f1453993f40af79784d073972601595978b6add52314c6fe119501cc458ce3140fdee9a708fe96ec789623af991a9df00a1542043f01fb784adf0b8c0a" ++ "09edf0c2df8386c3c430078b81830cddf7edd9777cd87e29aef6da7949297ba18b02ebab57b4dd0d56ada30b28c51a5c0ec2ae835b3142cdcacdfa1103e68d89" ++ "72f7b8007186ac174773e25c09d22bdecbd146c5fd4945040bf01e55ac0b35a735eda9f01763c9b1abc720e1bad89aac6e622c3bc3147a47dc1d04bc31e5a8d8" ++ "e95063930c41ac71a238fccfccda7fa86a1cab28b693fa72f0e9a6375d43442ca4ab378dc97f105f832da99b97db13dc7be935786f463092613d7e1f4339751a" ++ "9b82e1365ee0cf9bb51c861a7266d4a752eaf7953827fcb3b71101bdefcea84e");
const server_shared_secret = hex("ec6df2d16f01e483e1ab7af5aa02570c42cd757f0ac70b7d56b96b068d9b9bb2e9f37349d5d07834f2ee53117f67d42a04fe7f8adc4a000af04e291d9e151f0a");

const ek_len = kx.HybridKx.mlkem_public_len;
const ct_len = kx.HybridKx.mlkem_ciphertext_len;

fn clientKeyPair() !kx.HybridKx.KeyPair {
    return kx.HybridKx.generateDeterministic(client_x25519_sk ++ client_mlkem_seed);
}

/// The client-side combine exactly as `tls_client.zig` does it for 0x11ec.
fn clientDecap(pair: *const kx.HybridKx.KeyPair, share: [ct_len + kx.X25519Kx.public_len]u8) ![64]u8 {
    var ss: [64]u8 = undefined;
    const mlkem_ss = try pair.mlkem.secret_key.decaps(share[0..ct_len]);
    var x_secret = try kx.X25519Kx.sharedSecret(&pair.x25519.secret_key, share[ct_len..].*);
    defer x_secret.wipe();
    ss[0..32].* = mlkem_ss;
    ss[32..64].* = x_secret.declassify();
    return ss;
}

test "X25519MLKEM768 client key_share matches the OpenSSL-derived vector" {
    try std.testing.expectEqual(@as(usize, 1216), client_share.len);
    var pair = try clientKeyPair();
    defer pair.wipe();
    const pub_share = pair.publicShare();
    try std.testing.expectEqualSlices(u8, client_share[0..ek_len], &pub_share.mlkem_public_key);
    try std.testing.expectEqualSlices(u8, client_share[ek_len..], &pub_share.x25519_public_key);
}

test "X25519MLKEM768 client decap of an OpenSSL hybrid encapsulation (ml-kem ss || x25519 ss)" {
    var pair = try clientKeyPair();
    defer pair.wipe();
    const ss = try clientDecap(&pair, openssl_server_share);
    try std.testing.expectEqualSlices(u8, &openssl_shared_secret, &ss);
    // The reverse (x25519 ss || ml-kem ss) order must not match.
    var swapped: [64]u8 = undefined;
    swapped[0..32].* = ss[32..64].*;
    swapped[32..64].* = ss[0..32].*;
    try std.testing.expect(!std.mem.eql(u8, &openssl_shared_secret, &swapped));
}

test "X25519MLKEM768 server encapsulation matches the OpenSSL-derived vector" {
    // Server side as in tls_server.zig: encaps against the client ek with the
    // given randomness, X25519 against the client's classical half.
    const pk = try MlKem.PublicKey.fromBytes(client_share[0..ek_len]);
    const enc = pk.encapsDeterministic(&server_ikme);
    var srv_x = try kx.X25519Kx.generateDeterministic(server_x25519_sk);
    defer srv_x.wipe();
    var x_secret = try kx.X25519Kx.sharedSecret(&srv_x.secret_key, client_share[ek_len..].*);
    defer x_secret.wipe();

    try std.testing.expectEqualSlices(u8, server_share[0..ct_len], &enc.ciphertext);
    try std.testing.expectEqualSlices(u8, server_share[ct_len..], &srv_x.public_key);
    try std.testing.expectEqualSlices(u8, server_shared_secret[0..32], &enc.shared_secret);
    try std.testing.expectEqualSlices(u8, server_shared_secret[32..], &x_secret.declassify());

    // And the client recovers the same 64-byte secret from that share.
    var pair = try clientKeyPair();
    defer pair.wipe();
    const ss = try clientDecap(&pair, server_share);
    try std.testing.expectEqualSlices(u8, &server_shared_secret, &ss);
}
