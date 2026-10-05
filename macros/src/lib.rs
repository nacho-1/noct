//! The ecl-macros crate contains the `test` macro.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Used to mark an application test.
///
/// Test functions marked with this attribute receive a [`noct-web::test_helpers::TestContext`]
/// struct via which they get access a preconfigured instance of the application.
/// The application instance is extended with convenience methods for making requests from the test.
#[proc_macro_attribute]
pub fn test(_: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let test_attrs = input.attrs;
    let test_name = input.sig.ident.clone();
    let test_arguments = input.sig.inputs;
    let test_block = input.block;
    let inner_test_name = syn::Ident::new(
        format!("inner_{}", test_name).as_str(),
        input.sig.ident.span(),
    );

    let setup = quote! {
        let context = noct_web::test_helpers::setup().await;
    };

    let output = quote!(
        #[::tokio::test]
        #(#test_attrs)*
        async fn #test_name() {
            #setup
            async fn #inner_test_name(#test_arguments) #test_block
            #inner_test_name(&context).await;
        }
    );

    TokenStream::from(output)
}

