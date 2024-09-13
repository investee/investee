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

#![recursion_limit = "128"]

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use syn::spanned::Spanned;

/// Attribute to declare the init function of a plugin
/// ``` no_run
/// #[plugin_init]
/// fn plugin_init() -> Result<()> {}
/// ```
#[proc_macro_attribute]
pub fn plugin_init(_args: TokenStream, input: TokenStream) -> TokenStream {
    let f = parse_macro_input!(input as syn::ItemFn);
    let f_vis = &f.vis;
    let f_block = &f.block;
    let f_decl = &f.decl;
    let f_inputs = &f_decl.inputs;

    // check the function signature
    let valid_signature = f.constness.is_none()
        && match f_vis {
            syn::Visibility::Inherited => true,
            _ => false,
        }
        && f.abi.is_none()
        && f_inputs.len() == 0
        && f.decl.generics.where_clause.is_none()
        && f.decl.variadic.is_none();

    if !valid_signature {
        return syn::parse::Error::new(
            f.span(),
            "`#[plugin_init]` function must have signature `fn()`",
        )
        .to_compile_error()
        .into();
    }

    quote!(
        #[no_mangle]
        pub fn _plugin_init() -> optee_teec::Result<()> {
            #f_block
            Ok(())
        }
    )
    .into()

}

/// Attribute to declare the invoke function of a plugin
/// ``` no_run
/// #[plugin_invoke]
/// fn plugin_invoke(params: &mut PluginParameters) {}
/// ```
#[proc_macro_attribute]
pub fn plugin_invoke(_args: TokenStream, input: TokenStream) -> TokenStream {
    let f = parse_macro_input!(input as syn::ItemFn);
    let f_vis = &f.vis;
    let f_block = &f.block;
    let f_decl = &f.decl;
    let f_inputs = &f_decl.inputs;

    // check the function signature
    let valid_signature = f.constness.is_none()
        && match f_vis {
            syn::Visibility::Inherited => true,
            _ => false,
        }
        && f.abi.is_none()
        && f_inputs.len() == 1
        && f.decl.generics.where_clause.is_none()
        && f.decl.variadic.is_none();

    if !valid_signature {
        return syn::parse::Error::new(
            f.span(),
            "`#[plugin_invoke]` function must have signature `fn(params: &mut PluginParamters)`",
        )
        .to_compile_error()
        .into();
    }

    quote!(
        #[no_mangle]
        pub fn _plugin_invoke(
            cmd: u32,
            sub_cmd: u32,
            data: *mut c_char,
            in_len: u32,
            out_len: *mut u32
        ) -> optee_teec::Result<()> {
            let mut inbuf = unsafe { std::slice::from_raw_parts_mut(data, in_len as usize) };
            let mut params = PluginParameters::new(cmd, sub_cmd, inbuf);
            #f_block
            let outslice = params.get_out_slice();
            unsafe {
                *out_len = outslice.len() as u32;
                std::ptr::copy(outslice.as_ptr(), data, outslice.len());
            }

            Ok(())
        }
    )
    .into()

}
