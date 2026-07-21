// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Feature-aware HPKE request routing.

#[cfg(all(feature = "hpke", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::__buffa::oneof::crypto_operation_result::Result as CryptoOperationResultBranch;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHpkeDeriveKeyPairRequest, CryptoHpkeGenerateKeyPairRequest, CryptoHpkeOpenRequest,
    CryptoHpkePskOpenRequest, CryptoHpkePskSealRequest, CryptoHpkeReceiverExportRequest,
    CryptoHpkeSealRequest, CryptoHpkeSenderExportRequest, CryptoOperationResponse,
};

#[cfg(all(feature = "hpke", any(feature = "native", feature = "wasm")))]
use super::request::process_request;

macro_rules! hpke_request_handler {
    ($name:ident, $request:ty, $process:ident, $result:ident) => {
        pub(super) fn $name(request: $request) -> CryptoOperationResponse {
            #[cfg(all(feature = "hpke", any(feature = "native", feature = "wasm")))]
            {
                process_request(
                    request,
                    super::hpke::$process,
                    CryptoOperationResultBranch::$result,
                )
            }
            #[cfg(not(all(feature = "hpke", any(feature = "native", feature = "wasm"))))]
            {
                let _ = request;
                super::request::unsupported_response()
            }
        }
    };
}

hpke_request_handler!(
    process_hpke_seal_request,
    CryptoHpkeSealRequest,
    process_hpke_seal,
    HpkeSeal
);
hpke_request_handler!(
    process_hpke_open_request,
    CryptoHpkeOpenRequest,
    process_hpke_open,
    HpkeOpen
);
hpke_request_handler!(
    process_hpke_generate_key_pair_request,
    CryptoHpkeGenerateKeyPairRequest,
    process_hpke_generate_key_pair,
    HpkeGenerateKeyPair
);
hpke_request_handler!(
    process_hpke_derive_key_pair_request,
    CryptoHpkeDeriveKeyPairRequest,
    process_hpke_derive_key_pair,
    HpkeDeriveKeyPair
);
hpke_request_handler!(
    process_hpke_sender_export_request,
    CryptoHpkeSenderExportRequest,
    process_hpke_sender_export,
    HpkeSenderExport
);
hpke_request_handler!(
    process_hpke_receiver_export_request,
    CryptoHpkeReceiverExportRequest,
    process_hpke_receiver_export,
    HpkeReceiverExport
);
hpke_request_handler!(
    process_hpke_psk_seal_request,
    CryptoHpkePskSealRequest,
    process_hpke_psk_seal,
    HpkePskSeal
);
hpke_request_handler!(
    process_hpke_psk_open_request,
    CryptoHpkePskOpenRequest,
    process_hpke_psk_open,
    HpkePskOpen
);
