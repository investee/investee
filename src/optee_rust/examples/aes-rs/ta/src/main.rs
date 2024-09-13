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
use optee_utee::{is_algorithm_supported};
use optee_utee::{AlgorithmId, ElementId, Cipher, OperationMode};
use optee_utee::{AttributeId, AttributeMemref, TransientObject, TransientObjectType};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::{Algo, Command, KeySize, Mode};
use std::boxed::Box;

pub struct AesCipher {
    pub key_size: usize,
    pub cipher: Cipher,
    pub key_object: TransientObject,
}

impl Default for AesCipher {
    fn default() -> Self {
        Self {
            key_size: 0,
            cipher: Cipher::null(),
            key_object: TransientObject::null_object(),
        }
    }
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut AesCipher) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut AesCipher) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destory");
}

#[ta_invoke_command]
fn invoke_command(sess_ctx: &mut AesCipher, cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::Prepare => {
            return alloc_resources(sess_ctx, params);
        }
        Command::SetKey => {
            return set_aes_key(sess_ctx, params);
        }
        Command::SetIV => {
            return reset_aes_iv(sess_ctx, params);
        }
        Command::Cipher => {
            return cipher_buffer(sess_ctx, params);
        }
        _ => {
            return Err(Error::new(ErrorKind::BadParameters));
        }
    }
}

pub fn ta2tee_algo_id(algo_id: u32) -> Result<AlgorithmId> {
    match Algo::from(algo_id) {
        Algo::ECB => Ok(AlgorithmId::AesEcbNopad),
        Algo::CBC => Ok(AlgorithmId::AesCbcNopad),
        Algo::CTR => Ok(AlgorithmId::AesCtr),
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

pub fn ta2tee_key_size(key_sz: u32) -> Result<usize> {
    match KeySize::from(key_sz) {
        KeySize::Bit128 | KeySize::Bit256 => Ok(key_sz as usize),
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

pub fn ta2tee_mode_id(mode: u32) -> Result<OperationMode> {
    match Mode::from(mode) {
        Mode::Encode => Ok(OperationMode::Encrypt),
        Mode::Decode => Ok(OperationMode::Decrypt),
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

pub fn alloc_resources(aes: &mut AesCipher, params: &mut Parameters) -> Result<()> {
    let algo_value = unsafe { params.0.as_value().unwrap().a() };
    let key_size_value = unsafe { params.1.as_value().unwrap().a() };
    let mode_id_value = unsafe { params.2.as_value().unwrap().a() };

    aes.key_size = ta2tee_key_size(key_size_value).unwrap();

    // check whether the algorithm is supported
    is_algorithm_supported(ta2tee_algo_id(algo_value).unwrap() as u32, ElementId::ElementNone as u32)?;

    aes.cipher = Cipher::allocate(
        ta2tee_algo_id(algo_value).unwrap(),
        ta2tee_mode_id(mode_id_value).unwrap(),
        aes.key_size * 8,
    )
    .unwrap();
    aes.key_object = TransientObject::allocate(TransientObjectType::Aes, aes.key_size * 8).unwrap();
    let key = vec![0u8; aes.key_size as usize];
    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &key);
    aes.key_object.populate(&[attr.into()])?;
    aes.cipher.set_key(&aes.key_object)?;
    Ok(())
}

pub fn set_aes_key(aes: &mut AesCipher, params: &mut Parameters) -> Result<()> {
    let mut param0 = unsafe { params.0.as_memref().unwrap() };
    let key = param0.buffer();

    if key.len() != aes.key_size {
        trace_println!("[+] Get wrong key size !\n");
        return Err(Error::new(ErrorKind::BadParameters));
    }

    let attr = AttributeMemref::from_ref(AttributeId::SecretValue, &key);

    aes.key_object.reset();
    aes.key_object.populate(&[attr.into()])?;

    aes.cipher.set_key(&aes.key_object)?;
    Ok(())
}

pub fn reset_aes_iv(aes: &mut AesCipher, params: &mut Parameters) -> Result<()> {
    let mut param0 = unsafe { params.0.as_memref().unwrap() };
    let iv = param0.buffer();

    aes.cipher.init(iv);

    trace_println!("[+] TA initial vectore reset done!");
    Ok(())
}

pub fn cipher_buffer(aes: &mut AesCipher, params: &mut Parameters) -> Result<()> {
    let mut param0 = unsafe { params.0.as_memref().unwrap() };
    let mut param1 = unsafe { params.1.as_memref().unwrap() };

    let input = param0.buffer();
    let output = param1.buffer();

    if output.len() < input.len() {
        return Err(Error::new(ErrorKind::BadParameters));
    }

    trace_println!("[+] TA tries to update ciphers!");

    let tmp_size = aes.cipher.update(input, output).unwrap();
    param1.set_updated_size(tmp_size);
    Ok(())
}

const TA_FLAGS: u32 = 0;
const TA_STACK_SIZE: u32 = 2 * 1024;
const TA_DATA_SIZE: u32 = 1 * 1024 * 1024;
const TA_VERSION: &[u8] = b"Undefined version\0";
const TA_DESCRIPTION: &[u8] = b"This is an AES example\0";
const EXT_PROP_VALUE_1: &[u8] = b"AES TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
