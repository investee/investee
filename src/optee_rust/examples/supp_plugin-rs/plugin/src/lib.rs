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

use libc::{c_char};
use optee_teec::{Error, ErrorKind, PluginMethod, PluginParameters};
use optee_teec::{plugin_init, plugin_invoke};
use proto::{PluginCommand};

#[plugin_init]
fn init() {
    println!("*plugin*: init");
}

#[plugin_invoke]
fn invoke(params: &mut PluginParameters) {
    println!("*plugin*: invoke");
    match PluginCommand::from(params.cmd) {
        PluginCommand::Print => {
            println!("*plugin*: receive value: {:?} length {:?}", params.inout, params.inout.len());

            let send_slice: [u8;9] = [0x40;9];
            params.set_buf_from_slice(&send_slice)?;
            println!("*plugin*: send value: {:?} length {:?} to ta", send_slice, send_slice.len());
        }
        _ => println!("Unsupported plugin command: {:?}", params.cmd),
    }
}


include!(concat!(env!("OUT_DIR"), "/plugin_static.rs"));
