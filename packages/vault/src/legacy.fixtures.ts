export const LEGACY = {
  "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  "password": "fixture password Å",
  "appDataInfo": "test/app-data/v1",
  "plaintext": "synthetic address book",
  "rows": [
    {
      "producer": "desktop",
      "argon2id": {
        "v": 1,
        "kdf": "argon2id",
        "kdfParams": {
          "m": 19456,
          "t": 2,
          "p": 1,
          "dkLen": 32
        },
        "salt": "9o/Ev/1iqmF7H0jYTRvFRg==",
        "iv": "vKKfHRk5oGjPfjYM",
        "ciphertext": "wrwog+W4pgiM5CjKhgqew1tiiuvEK4kB6UEWb5Bj/yCA6AImZQnm+yeHGf17J8m4uer2+bxANhWJEweRIaIQn5FcWfKOnTaqDavtM4/LQXMRFRoWTgb2vGGPcXH3ecbZiCztH8FBr8Nkemp2Jg=="
      },
      "scrypt": {
        "v": 1,
        "kdf": "scrypt",
        "kdfParams": {
          "N": 16384,
          "r": 8,
          "p": 1,
          "dkLen": 32
        },
        "salt": "9LbZgyy7ljVxgwE3UedEaA==",
        "iv": "HbmdzqIMpyCgWT9T",
        "ciphertext": "AOkPWhrB2quJWQso5MJMARF1xOQ+KGXtL97WDsC+0WQzk7FTurXjZ1U51+Qjfp4seUdW3PspfS5icBCOaqFniIIcL9hHMCT9/R3uSUgDecY4ncjUHTYttMvzKE62HtrYJWDmbrM6UfBfChy1xQ=="
      },
      "appData": "{\"v\":1,\"iv\":\"gzA3q01EeuaMJc+i\",\"ct\":\"79M1xB7yVLWKwuTHA1P+Ym5onKRowXd80jKu1l4S0oqZv+NH3Cw=\"}",
      "masterPrivateKey": "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
    },
    {
      "producer": "extension",
      "argon2id": {
        "v": 1,
        "kdf": "argon2id",
        "kdfParams": {
          "m": 19456,
          "t": 2,
          "p": 1,
          "dkLen": 32
        },
        "salt": "+1afI8QCSmL6nmU7xzDCUA==",
        "iv": "CANDeKOQ1j94jsVJ",
        "ciphertext": "GogXuAFHPLNMgKN29n7WFUU8ULVD4eOYYIatiZD5BsC+Hd6Yk6CBYDNOfJqDN28Yzx3tVV8HG4TEdVUrmakuhlltO3HysQeQXGmFZdr40PAAkSjux3E1UvLDYSrKtaVHKJ4j26fTVgHR+/LMEg=="
      },
      "scrypt": {
        "v": 1,
        "kdf": "scrypt",
        "kdfParams": {
          "N": 16384,
          "r": 8,
          "p": 1,
          "dkLen": 32
        },
        "salt": "2FuzhFYAYWJhaoYqo1c8og==",
        "iv": "i+mbS+KAnVVaRTM3",
        "ciphertext": "f7ejyMZ8TNYXwfKk3UoMqGzUo7menKryMaOj/7VNjortE2JDKjf7xHtWVbbp5t7bDoqUV2ZoIpkh83IuxNOU0RzIeEOhT/loA/KEZ4oUFTBn0mJvcLC+kv19WoJWNDfoePfD2MrwxyFYT9RjVg=="
      },
      "appData": "{\"v\":1,\"iv\":\"SVbfkygffJGvITS2\",\"ct\":\"1p1J5ysMvZkq9xupZaxB8MUpyxqMdN5pd/+WJ4WMKY2u8TWnh1g=\"}",
      "masterPrivateKey": "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
    }
  ]
} as const;
