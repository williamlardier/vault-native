{
  "targets": [
    {
      "target_name": "vault_crypto_native",
      "sources": ["src/vault_crypto.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "libraries": [
        "-lcrypto",
        "-lssl"
      ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "cflags": [ 
        "-mavx2", 
        "<!(echo ${VAULT_CRYPTO_OPT_LEVEL:-'-O2'})", 
        "-march=native", 
        "-ftree-vectorize",
        "-ffast-math"
      ],
      "cflags_cc": [ 
        "-mavx2", 
        "<!(echo ${VAULT_CRYPTO_OPT_LEVEL:-'-O2'})", 
        "-march=native", 
        "-ftree-vectorize",
        "-ffast-math"
      ],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "10.7"
      },
      "msvs_settings": {
        "VCCLCompilerTool": { "ExceptionHandling": 1 }
      },
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ]
    }
  ]
}