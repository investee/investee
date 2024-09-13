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

#![no_main]

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{AlgorithmId, DeriveKey};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Command, KEY_SIZE};

pub struct DiffieHellman {
    pub key: TransientObject,
}

impl Default for DiffieHellman {
    fn default() -> Self {
        Self {
            key: TransientObject::null_object(),
        }
    }
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut DiffieHellman) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut DiffieHellman) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

fn generate_key(dh: &mut DiffieHellman, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_value().unwrap() };
    let mut p2 = unsafe { params.2.as_memref().unwrap() };
    let mut p3 = unsafe { params.3.as_memref().unwrap() };

    // Extract prime and base from parameters
    let prime_base_vec = p0.buffer();
    let prime_slice = &prime_base_vec[..KEY_SIZE/8];
    let base_slice = &prime_base_vec[KEY_SIZE/8..];

    let attr_prime = AttributeMemref::from_ref(AttributeId::DhPrime, prime_slice);
    let attr_base = AttributeMemref::from_ref(AttributeId::DhBase, base_slice);

    // Generate key pair
    dh.key = TransientObject::allocate(TransientObjectType::DhKeypair, KEY_SIZE).unwrap();
    let mut public_buffer = p2.buffer();
    let mut private_buffer = p3.buffer();

    dh.key
        .generate_key(KEY_SIZE, &[attr_prime.into(), attr_base.into()])?;
    let mut key_size = dh
        .key
        .ref_attribute(AttributeId::DhPublicValue, &mut public_buffer)
        .unwrap();
    p1.set_a(key_size as u32);
    key_size = dh
        .key
        .ref_attribute(AttributeId::DhPrivateValue, &mut private_buffer)
        .unwrap();
    p1.set_b(key_size as u32);
    Ok(())
}

fn derive_key(dh: &mut DiffieHellman, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut p1 = unsafe { params.1.as_memref().unwrap() };
    let mut p2 = unsafe { params.2.as_value().unwrap() };

    let received_public = AttributeMemref::from_ref(AttributeId::DhPublicValue, p0.buffer());

    match DeriveKey::allocate(AlgorithmId::DhDeriveSharedSecret, KEY_SIZE) {
        Err(e) => Err(e),
        Ok(operation) => {
            operation.set_key(&dh.key)?;
            let mut derived_key =
                TransientObject::allocate(TransientObjectType::GenericSecret, KEY_SIZE).unwrap();
            operation.derive(&[received_public.into()], &mut derived_key);
            let key_size = derived_key
                .ref_attribute(AttributeId::SecretValue, p1.buffer())
                .unwrap();
            p2.set_a(key_size as u32);
            Ok(())
        }
    }
}

#[ta_invoke_command]
fn invoke_command(
    sess_ctx: &mut DiffieHellman,
    cmd_id: u32,
    params: &mut Parameters,
) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::GenerateKey => {
            return generate_key(sess_ctx, params);
        }
        Command::DeriveKey => {
            return derive_key(sess_ctx, params);
        }
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024;
const TA_STACK_SIZE: u32 = 2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is an example which serves DH related functions.\0";
const EXT_PROP_VALUE_1: &[u8] = b"DH TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
