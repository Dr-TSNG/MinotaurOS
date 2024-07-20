use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[proc_macro_attribute]
pub fn suspend(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;
    let expanded = quote! {
        #vis #sig {
            use core::pin::pin;
            use crate::sched::suspend_now;
            use crate::process::thread::event_bus::Event;
            let fut = async move #block;
            suspend_now(None, Event::all(), pin!(fut)).await
        }
    };
    TokenStream::from(expanded)
}
