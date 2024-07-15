use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::parse_macro_input;

struct SimpleInodeArgs {
    fs: syn::Type,
    typ: syn::Ident,
    name: syn::LitStr,
    path: syn::LitStr,
}

impl Parse for SimpleInodeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let fs = input.parse::<syn::Type>()?;
        let typ = input.parse::<syn::Ident>()?;
        let name = input.parse::<syn::LitStr>()?;
        let path = input.parse::<syn::LitStr>()?;
        Ok(Self { fs, typ, name, path })
    }
}

#[proc_macro_attribute]
pub fn simple_inode(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as SimpleInodeArgs);


    input
}
