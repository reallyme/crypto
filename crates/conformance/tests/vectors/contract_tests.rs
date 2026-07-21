// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::support::{field_array, field_string, load, VectorTestError};

include!("contract_tests/constants.rs");
include!("contract_tests/support.rs");
include!("contract_tests/protobuf_algorithm_tests.rs");
include!("contract_tests/protobuf_operation_contract_tests.rs");
include!("contract_tests/repository_shape_tests.rs");
include!("contract_tests/package_policy_tests.rs");
