// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

pub use self::context::Context;
pub use self::error::{Error, ErrorKind, Result};
pub use self::operation::Operation;
pub use self::parameter::{Param, ParamNone, ParamTmpRef, ParamType, ParamTypes, ParamValue};
pub use self::session::{ConnectionMethods, Session};
pub use self::uuid::Uuid;
pub use self::extension::*;
pub use optee_teec_macros::{plugin_init, plugin_invoke};

mod context;
mod error;
mod operation;
mod parameter;
mod session;
mod uuid;
mod extension;
