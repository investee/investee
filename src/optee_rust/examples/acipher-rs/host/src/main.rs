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

use optee_teec::{Context, Operation, ParamType, Session, Uuid};
use optee_teec::{Error, ErrorKind, ParamNone, ParamTmpRef, ParamValue};
use proto::{Command, UUID};
use std::{env, str};

fn gen_key(session: &mut Session, key_size: u32) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(key_size, 0, ParamType::ValueInput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::GenKey as u32, &mut operation)?;

    Ok(())
}

fn enc_dec(session: &mut Session, plain_text: &[u8]) -> optee_teec::Result<()> {
    let p0 = ParamValue::new(0, 0, ParamType::ValueOutput);
    let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::GetSize as u32, &mut operation)?;

    let mut cipher_text = vec![0u8; operation.parameters().0.a() as usize];
    let p0 = ParamTmpRef::new_input(plain_text);
    let p1 = ParamTmpRef::new_output(&mut cipher_text);
    let mut operation2 = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::Encrypt as u32, &mut operation2)?;
    println!(
        "Success encrypt input text \"{}\" as {} bytes cipher text: {:?}",
        str::from_utf8(plain_text).unwrap(),
        cipher_text.len(),
        cipher_text
    );

    let p0 = ParamTmpRef::new_input(&cipher_text);
    let mut dec_res: Vec<u8> = vec![0u8; plain_text.len()];
    let p1 = ParamTmpRef::new_output(&mut dec_res);
    let mut operation2 = Operation::new(0, p0, p1, ParamNone, ParamNone);

    session.invoke_command(Command::Decrypt as u32, &mut operation2)?;
    println!(
        "Success decrypt the above ciphertext as {} bytes plain text: {}",
        dec_res.len(),
        str::from_utf8(&dec_res).unwrap()
    );
    Ok(())
}

fn main() -> optee_teec::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!(
            "Receive {} arguments while 2 arguments are expected!",
            args.len()
        );
        println!("Correct usage: passed 2 arguments as <key_size> and <string to encrypt>");
        return Err(Error::new(ErrorKind::BadParameters));
    }

    let mut key_size = args[1].parse::<u32>().unwrap();
    if key_size < 256 {
        println!(
            "Wrong key size {} is received. Use default minimal key size 256 instead.",
            key_size
        );
        key_size = 256;
    }

    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    gen_key(&mut session, key_size)?;
    enc_dec(&mut session, args[2].as_bytes())?;

    Ok(())
}
