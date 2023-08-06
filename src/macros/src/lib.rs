use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Index};

#[proc_macro_derive(Sign, attributes(digest_with_sig))]
pub fn derive_digest(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let digest = impl_digest(&input.data);
    let expanded = quote! {
        impl Digestible for #name { #digest }
        impl Signable for #name {
            fn public_key(&self) -> ed25519_dalek::VerifyingKey { self.public_key.into() }
            fn signature(&self) -> ed25519_dalek::Signature { self.signature.into() }
            fn sign(&mut self, kp: ed25519_dalek::SigningKey) {
                self.public_key = ws_common::b64e::Base64(kp.verifying_key());
                self.signature = ws_common::b64e::Base64(kp.sign(self.digest().as_bytes()).to_bytes());
            }
        }
    };
    proc_macro::TokenStream::from(expanded)
}

fn impl_digest(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let sig = Some(Ident::new("signature", Span::call_site()));
                let sigdig = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    // signature field should not be part of the digest unless nested struct
                    // (since we are taking the sigless digest of the outermost struct only)
                    if f.attrs
                        .clone()
                        .into_iter()
                        .any(|attr| attr.path().get_ident().unwrap() == "digest_with_sig")
                    {
                        quote_spanned! {f.span()=> self.#name.digest_with_sig(), }
                    } else {
                        quote_spanned! {f.span()=> self.#name.digest(), }
                    }
                });
                let nosigdig = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    // signature field should not be part of the digest unless nested struct
                    // (since we are taking the sigless digest of the outermost struct only)
                    if *name == sig {
                        quote!()
                    } else if f
                        .attrs
                        .clone()
                        .into_iter()
                        .any(|attr| attr.path().get_ident().unwrap() == "digest_with_sig")
                    {
                        quote_spanned! {f.span()=> self.#name.digest_with_sig(), }
                    } else {
                        quote_spanned! {f.span()=> self.#name.digest(), }
                    }
                });
                quote! {
                    fn digest(&self) -> String { [#(#nosigdig)*].join(":") }
                    fn digest_with_sig(&self) -> String { [#(#sigdig)*].join(":") }
                }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    if f.attrs
                        .clone()
                        .into_iter()
                        .any(|attr| attr.path().get_ident().unwrap() == "digest_with_sig")
                    {
                        quote_spanned! {f.span()=> self.#index.digest_with_sig(), }
                    } else {
                        quote_spanned! {f.span()=> self.#index.digest(), }
                    }
                });
                quote! { #(#recurse)* }
            }
            Fields::Unit => {
                quote!("",)
            }
        },
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

#[proc_macro_derive(Timestamped)]
pub fn derive_timestamped(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let expanded = quote! {
        impl Timestamped for #name {
            fn timestamp(&self) -> crate::api::timestamp::Timestamp {
                return self.timestamp
            }
        }
    };
    proc_macro::TokenStream::from(expanded)
}
