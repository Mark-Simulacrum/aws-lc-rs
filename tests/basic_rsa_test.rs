// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use aws_lc_rust::rand::SystemRandom;
use aws_lc_rust::signature;
use aws_lc_rust::signature::RsaKeyPair;
use aws_lc_rust::test::from_dirty_hex;

#[test]
fn test_rsa_pkcs8() {
    let rsa_pkcs8_input: Vec<u8> = from_dirty_hex(
        r#"308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b9d7a
        f84fa4184a5f22037ec8aff2db5f78bd8c21e714e579ae57c6398c4950f3a694b17bfccf488766159aec5bb7c2c4
        3d59c798cbd45a09c9c86933f126879ee7eadcd404f61ecfc425197cab03946ba381a49ef3b4d0f60b17f8a747cd
        e56a834a7f6008f35ffb2f60a54ceda1974ff2a9963aba7f80d4e2916a93d8c74bb1ba5f3b189a4e8f0377bd3e94
        b5cc3f9c53cb8c8c7c0af394818755e968b7a76d9cada8da7af5fbe25da2a09737d5e4e4d7092aa16a0718d7322c
        e8aca767015128d6d35775ea9cb8bb1ac6512e1b787d34015221be780a37b1d69bc3708bfd8832591be6095a768f
        0fd3b3457927e6ae3641d55799a29a0a269cb4a693bc14b0203010001028201001c5fb7e69fa6dd2fd0f5e653f12
        ce0b7c5a1ce6864e97bc2985dad4e2f86e4133d21d25b3fe774f658cca83aace9e11d8905d62c20b6cd28a680a77
        357cfe1afac201f3d1532898afb40cce0560bedd2c49fc833bd98da3d1cd03cded0c637d4173e62de865b572d410
        f9ba83324cd7a3573359428232f1628f6d104e9e6c5f380898b5570201cf11eb5f7e0c4933139c7e7fba67582287
        ffb81b84fa81e9a2d9739815a25790c06ead7abcf286bd43c6e3d009d01f15fca3d720bbea48b0c8ccf8764f3c82
        2e61159d8efcbff38c794f8afe040b45df14c976a91b1b6d886a55b8e68969bcb30c7197920d97d7721d78d954d8
        9ffecbcc93c6ee82a86fe754102818100eba1cbe453f5cb2fb7eabc12d697267d25785a8f7b43cc2cb14555d3618
        c63929b19839dcd4212397ecda8ad872f97ede6ac95ebda7322bbc9409bac2b24ae56ad62202800c670365ae2867
        1195fe934978a5987bee2fcea06561b782630b066b0a35c3f559a281f0f729fc282ef8ebdbb065d60000223da6ed
        b732fa32d82bb02818100c9e81e353315fd88eff53763ed7b3859f419a0a158f5155851ce0fe6e43188e44fb43dd
        25bcdb7f3839fe84a5db88c6525e5bcbae513bae5ff54398106bd8ae4d241c082f8a64a9089531f7b57b09af5204
        2efa097140702dda55a2141c174dd7a324761267728a6cc4ce386c034393d855ebe985c4e5f2aec2bd3f2e2123ab
        1028180566889dd9c50798771397a68aa1ad9b970e136cc811676ac3901c51c741c48737dbf187de8c47eec68acc
        05b8a4490c164230c0366a36c2c52fc075a56a3e7eecf3c39b091c0336c2b5e00913f0de5f62c5046ceb9d88188c
        c740d34bd44839bd4d0c346527cea93a15596727d139e53c35eed25043bc4ac18950f237c02777b0281800f9dd98
        049e44088efee6a8b5b19f5c0d765880c12c25a154bb6817a5d5a0b798544aea76f9c58c707fe3d4c4b3573fe7ad
        0eb291580d22ae9f5ccc0d311a40590d1af1f3236427c2d72f57367d3ec185b9771cb5d041a8ab93409e59a9d68f
        99c72f91c658a3fe5aed59f9f938c368530a4a45f4a7c7155f3906c4354030ef102818100c89e0ba805c970abd84
        a70770d8fc57bfaa34748a58b77fcddaf0ca285db91953ef5728c1be7470da5540df6af56bb04c0f5ec500f83b08
        057664cb1551e1e29c58d8b1e9d70e23ed57fdf9936c591a83c1dc954f6654d4a245b6d8676d045c2089ffce537d
        234fc88e98d92afa92926c75b286e8fee70e273d762bbe63cd63b"#,
    );

    let key = RsaKeyPair::from_pkcs8(&rsa_pkcs8_input);
    assert!(key.is_ok());
}

#[test]
fn test_rsa_from_der() {
    let rsa_key_input: Vec<u8> = from_dirty_hex(
        r#"308204a40201000282010100cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd72cc
        516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aefb920032a5bb989f8e4f5e1b05093d
        3f130f984c07a772a3683f4dc6fb28a96815b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924f
        fd04d30b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbfa2e02380582f3188bb94e
        bbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11813c84360bb53c7d4481031c40bad8713bb6b835cb08098ed
        15ba31ee4ba728a8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a043fb7fb78d0203260445028
        201000997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc9389709f8a11f3ea6a5af7effa2d0
        1c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dcd65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa
        1359d0e76e1f219f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e0f35a2f741644c1
        cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56b8af07193d0fdf3f49cd49f2ef3138b5138862f1470
        bd2d16e34a2b9e7777a6c8c8d4cb94b4e8b5d616cd5393753e7b0f31cc7da559ba8e98d888914e334773baf498ad
        88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d02818100f364e16ef12017ec95b192308c0
        1e087cee619ab50a5d537cc01841dc92b30bcef0d9f2c6bbd5dc10bdf5b9f6c354a4f9f210520caa72b4f5c36b8d
        33f10324c55956141891e45b84b49f59ea5bfac6ffa38900aca5099afcd02f6a8257c41ce5bb2e4153832b5c22f9
        1eb389fa2035c3cf9b3374531c483cb30ceb007259b1d02818100d95c0995fabdfcbccfe63e0f3262f806869ab57
        1e1793e97234cbb9bd4b6872a7695389955cf6ce7245345a5df8021f7d9519563afbc2667f5311fad093de2c02cd
        069109b630d68e3bf767f8a788a6add7ab199f2d8f6a40b7c1910d9dab52ac80d0d333aacab321a9309dc884ddd4
        db637a0c1115ae3c08efa683f99eb733102818100d4f7ef9f9be947ba9d1b3bce59e5608839a1e464553e1b6d113
        d0f636758bbb473a89f9949836ead40b6f314eee3ac2244d7b6f379e83f30e17783ad68d5086897889c051c26e15
        58a4a220bfc242995860644b5d7a3ef513ac612b9c6c0a2021bb6b9cde7dbd21fe5858746c79563e9bab7d06b43a
        ab43a0a5cafab4519a6610281803db2386f174f2ea3ef4b6bd1601749ce2d6afa8be35f051178621f16a23ad36eb
        a03c073136389241969e5b87edb0fcbcf1a0bd6e1aee97bae1f2d97aabe19b17dbe7d9492cdb68a0897f572350e8
        46c669660dc978c5068da598524fca8a136358d3e5f8f6ad5cf78d9089c93f473189162ce0f8c4902a19902b633b
        3e6926d02818100ddc971183dcf3450c43e06ba2af32379eedeb2d678513fb706b75a006098154041f4b09e6be38
        5d4b25d80ec241c899e4a986a17b0a121daab91a1e4fc5a1802a7074df3fb3f7661f0e1c97799e36d21de937cc42
        09585db30a56af0a228e001036ed792625e5368ce101574a2e9767f07338949f0afdf358cecd18c6d6f3f55"#,
    );

    let key = RsaKeyPair::from_der(&rsa_key_input);
    assert!(key.is_ok());
}

#[test]
fn test_sign() {
    let alg = &signature::RSA_PKCS1_SHA256;
    let private_key = from_dirty_hex(
        r#"308204a40201000282010100cea80475324c1dc8347827818da58bac069d3419c614a6ea1ac6a3b510dcd
            72cc516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef293771aefb920032a5bb989f8e4f5e
            1b05093d3f130f984c07a772a3683f4dc6fb28a96815b32123ccdd13954f19d5b8b24a103e771a34c328755c
            65ed64e1924ffd04d30b2142cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbfa2e02
            380582f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11813c84360bb53c7d4481031c40bad
            8713bb6b835cb08098ed15ba31ee4ba728a8c8e10f7294e1b4163b7aee57277bfd881a6f9d43e02c6925aa3a
            043fb7fb78d0203260445028201000997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1e15f66fc9
            389709f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1d388a9dcd65df8628902556c8b6
            bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1f219f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e1
            2e3c67cb629569c185a2e0f35a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56b8a
            f07193d0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c8c8d4cb94b4e8b5d616cd539375
            3e7b0f31cc7da559ba8e98d888914e334773baf498ad88d9631eb5fe32e53a4145bf0ba548bf2b0a50c63f67
            b14e398a34b0d02818100f364e16ef12017ec95b192308c01e087cee619ab50a5d537cc01841dc92b30bcef0
            d9f2c6bbd5dc10bdf5b9f6c354a4f9f210520caa72b4f5c36b8d33f10324c55956141891e45b84b49f59ea5b
            fac6ffa38900aca5099afcd02f6a8257c41ce5bb2e4153832b5c22f91eb389fa2035c3cf9b3374531c483cb3
            0ceb007259b1d02818100d95c0995fabdfcbccfe63e0f3262f806869ab571e1793e97234cbb9bd4b6872a769
            5389955cf6ce7245345a5df8021f7d9519563afbc2667f5311fad093de2c02cd069109b630d68e3bf767f8a7
            88a6add7ab199f2d8f6a40b7c1910d9dab52ac80d0d333aacab321a9309dc884ddd4db637a0c1115ae3c08ef
            a683f99eb733102818100d4f7ef9f9be947ba9d1b3bce59e5608839a1e464553e1b6d113d0f636758bbb473a
            89f9949836ead40b6f314eee3ac2244d7b6f379e83f30e17783ad68d5086897889c051c26e1558a4a220bfc2
            42995860644b5d7a3ef513ac612b9c6c0a2021bb6b9cde7dbd21fe5858746c79563e9bab7d06b43aab43a0a5
            cafab4519a6610281803db2386f174f2ea3ef4b6bd1601749ce2d6afa8be35f051178621f16a23ad36eba03c
            073136389241969e5b87edb0fcbcf1a0bd6e1aee97bae1f2d97aabe19b17dbe7d9492cdb68a0897f572350e8
            46c669660dc978c5068da598524fca8a136358d3e5f8f6ad5cf78d9089c93f473189162ce0f8c4902a19902b
            633b3e6926d02818100ddc971183dcf3450c43e06ba2af32379eedeb2d678513fb706b75a006098154041f4b
            09e6be385d4b25d80ec241c899e4a986a17b0a121daab91a1e4fc5a1802a7074df3fb3f7661f0e1c97799e36
            d21de937cc4209585db30a56af0a228e001036ed792625e5368ce101574a2e9767f07338949f0afdf358cecd
            18c6d6f3f55"#,
    );
    let msg = from_dirty_hex(
        r#"5af283b1b76ab2a695d794c23b35ca7371fc779e92ebf589e304c7f923d8cf97
        6304c19818fcd89d6f07c8d8e08bf371068bdf28ae6ee83b2e02328af8c0e2f96e528e16f852f1fc5455e4772e28
        8a68f159ca6bdcf902b858a1f94789b3163823e2d0717ff56689eec7d0e54d93f520d96e1eb04515abc70ae90578
        ff38d31b"#,
    );
    let expected = from_dirty_hex(
        r#"6b8be97d9e518a2ede746ff4a7d91a84a1fc665b52f154a927650db6e73
        48c69f8c8881f7bcf9b1a6d3366eed30c3aed4e93c203c43f5528a45de791895747ade9c5fa5eee81427edee0208
        2147aa311712a6ad5fb1732e93b3d6cd23ffd46a0b3caf62a8b69957cc68ae39f9993c1a779599cdda949bdaabab
        b77f248fcfeaa44059be5459fb9b899278e929528ee130facd53372ecbc42f3e8de2998425860406440f248d8174
        32de687112e504d734028e6c5620fa282ca07647006cf0a2ff83e19a916554cc61810c2e855305db4e5cf893a6a9
        6767365794556ff033359084d7e38a8456e68e21155b76151314a29875feee09557161cbc654541e89e42"#,
    );
    let key_pair = RsaKeyPair::from_der(&private_key).unwrap();

    let rng = SystemRandom::default();

    let mut actual = [0u8; 256];
    key_pair
        .sign(alg, &rng, &msg, actual.as_mut_slice())
        .unwrap();

    assert_eq!(&expected, &actual);
}

#[test]
fn test_rsa_verify() {
    let public_key = from_dirty_hex(
        r#"3082010c0282010100a1a78a0092878cb43263b218d75fc924e915ae
        80f1d32cd9db690c1c7cf6942ecdb54c0357e0a55f959d53562d1f89abbd59bc24a03557b068449d0753b927a5a6
        8921281fb92e61050fe838136ddd910ba13cd71b31045823b53d0a96e19ec97bd8dffb9923743060f84d6aabbdb4
        4eb0470b34dc3223a91b9e79f68cb86ba616aa5e62ead9627eccc110a72e2b03879c360bfcad3ab0e7f3184e7ac1
        54ee2803b2c7b57824c2fe54f600668087cba6778fdda5bd8dc1a60af7295a8c793520b0f02e35d16ef58e563b79
        29cb7045f9528e7a335888e5a2ad4a9f7539209924299f7640443bace8c643cf73c249fd43d616f111450baa403a
        9a8ce118af5e6902050100000001"#,
    );
    let msg = from_dirty_hex("");
    let sig = from_dirty_hex(
        r#"13b1addbef54e405580c0df21429fa030f3edfc7f7bd446907626d1e73e69dee
        8f5a2f1614f548e58b684da033dd8fbb7e9616408e1d1318698d10d536c622237febf2fc73d64718e791192d5c38
        326217cbfaa319e5fc1ce8cc4685d7d2f0b77c22fb11a0ce00467fbb918d5d0bf6926dd6b3bceefb15040f153abe
        5e3eb9c6ec80fe1064db69b332bf70cbeb2a483afcb09237420e1413941e2f71650cc393800efba739fecff9bf3a
        75b9ac88de483af0a0ee08d1a09f1de91f342017c53745fbe658a5980926ce56c14df45088d92e0bba61f16b8847
        d74f3fc707c60ba82af29face1c5269a54d4185e8efce9e566c3ca0c202ac1a4cc180d5320bf599a"#,
    );

    let params = &[
        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        &signature::RSA_PKCS1_2048_8192_SHA256,
    ];

    for &alg in params {
        let actual_result = signature::UnparsedPublicKey::new(alg, &public_key).verify(&msg, &sig);
        assert!(actual_result.is_ok(), "Rejected by: {alg:?}");
    }
}

#[test]
fn test_signature_rsa_primitive_verification() {
    let n = from_dirty_hex(
        r#"CEA80475324C1DC8347827818DA58BAC069D3419C614A6EA1AC6A3B510DCD72CC516954905E9FEF908D45
            E13006ADF27D467A7D83C111D1A5DF15EF293771AEFB920032A5BB989F8E4F5E1B05093D3F130F984C07A772
            A3683F4DC6FB28A96815B32123CCDD13954F19D5B8B24A103E771A34C328755C65ED64E1924FFD04D30B2142
            CC262F6E0048FEF6DBC652F21479EA1C4B1D66D28F4D46EF7185E390CBFA2E02380582F3188BB94EBBF05D31
            487A09AFF01FCBB4CD4BFD1F0A833B38C11813C84360BB53C7D4481031C40BAD8713BB6B835CB08098ED15BA
            31EE4BA728A8C8E10F7294E1B4163B7AEE57277BFD881A6F9D43E02C6925AA3A043FB7FB78D"#,
    );
    let e = from_dirty_hex(r#"260445"#);
    let msg = from_dirty_hex(r#"68656c6c6f2c20776f726c64"#);
    let sig = from_dirty_hex(
        r#"048efbc9eb5f7a6f55f6d7b9f7e6c3ce58e2db226562ca905e7f972e8f43b6969b0ad878e0d6b290c5bbf
            2c05410a1efc9de051d91e5faa537e454306f5f526c828379fe28a17e50c8bd4e7c834479da482305a78e198
            c988a177b9263cea27a2a99c0da98e03b0cc8d880eccdeba7c16dd07f78d980739753690953d1b63106145a8
            0059ed38f52100a9a8d2c7c5371d91b70ce5b7b36d6b97ebef8798d09c01e5b6cb8a6a7fd1a4100d3527327b
            7d23f8a26187985d8702f8951346ea4a7253e87f765ef587a728021bff37be55d1a8639809e3453ea5a2da48
            2bfedeae18579b51037cfecff5bece21d8c82ee6fa8eb0f43c43c3a23a983c3a2eea4e7d2dc"#,
    );

    let public_key = signature::RsaPublicKeyComponents { n: &n, e: &e };
    let result = public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, &msg, &sig);
    assert!(result.is_ok());
}
