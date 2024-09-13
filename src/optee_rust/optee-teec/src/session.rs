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

use libc;
use optee_teec_sys as raw;
use std::ptr;
use std::marker;

use crate::Param;
use crate::{Context, Error, Operation, Result, Uuid};

/// Session login methods.
#[derive(Copy, Clone)]
pub enum ConnectionMethods {
    /// No login data is provided.
    LoginPublic,
    /// Login data about the user running the Client Application process is provided.
    LoginUser,
    /// Login data about the group running the Client Application process is provided.
    LoginGroup,
    /// Login data about the running Client Application itself is provided.
    LoginApplication,
    /// Login data about the user and the running Client Application itself is provided.
    LoginUserApplication,
    /// Login data about the group and the running Client Application itself is provided.
    LoginGroupApplication,
}

/// Represents a connection between a client application and a trusted application.
pub struct Session<'ctx> {
    raw: raw::TEEC_Session,
    _marker: marker::PhantomData<&'ctx mut Context>,
}

impl<'ctx> Session<'ctx> {
    /// Initializes a TEE session object with specified context and uuid.
    pub fn new<A: Param, B: Param, C: Param, D: Param>(
        context: &'ctx mut Context,
        uuid: Uuid,
        operation: Option<&mut Operation<A, B, C, D>>,
    ) -> Result<Self> {
        let mut raw_session = raw::TEEC_Session {
            ctx: context.as_mut_raw_ptr(),
            session_id: 0,
        };
        let mut err_origin: u32 = 0;
        let raw_operation = match operation {
            Some(o) => o.as_mut_raw_ptr(),
            None => ptr::null_mut() as *mut raw::TEEC_Operation,
        };
        unsafe {
            match raw::TEEC_OpenSession(
                context.as_mut_raw_ptr(),
                &mut raw_session,
                uuid.as_raw_ptr(),
                ConnectionMethods::LoginPublic as u32,
                ptr::null() as *const libc::c_void,
                raw_operation,
                &mut err_origin,
            ) {
                raw::TEEC_SUCCESS => Ok(Self { raw: raw_session,  _marker: marker::PhantomData }),
                code => Err(Error::from_raw_error(code)),
            }
        }
    }

    /// Converts a TEE client context to a raw pointer.
    pub fn as_mut_raw_ptr(&mut self) -> *mut raw::TEEC_Session {
        &mut self.raw
    }

    /// Invokes a command with an operation with this session.
    pub fn invoke_command<A: Param, B: Param, C: Param, D: Param>(
        &mut self,
        command_id: u32,
        operation: &mut Operation<A, B, C, D>,
    ) -> Result<()> {
        let mut err_origin: u32 = 0;
        unsafe {
            match raw::TEEC_InvokeCommand(
                &mut self.raw,
                command_id,
                operation.as_mut_raw_ptr(),
                &mut err_origin,
            ) {
                raw::TEEC_SUCCESS => Ok(()),
                code => Err(Error::from_raw_error(code)),
            }
        }
    }
}

impl<'ctx> Drop for Session<'ctx> {
    fn drop(&mut self) {
        unsafe {
            raw::TEEC_CloseSession(&mut self.raw);
        }
    }
}
