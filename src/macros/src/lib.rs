use proc_macro2::{Ident, TokenStream};
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Index};

#[proc_macro_derive(Sign, attributes(digest_sig))]
pub fn derive_digest(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let digest = impl_digest(&input.data);
    let expanded = quote! {
        impl Signable for #name {
            fn digest(&self) -> String { [#digest].join(":") }
            fn public_key(&self) -> ed25519_dalek::VerifyingKey { self.public_key.into() }
            fn signature(&self) -> ed25519_dalek::Signature { self.signature.into() }
            fn sign(&mut self, kp: ed25519_dalek::SigningKey) {
                self.public_key = crate::b64e::Base64(kp.verifying_key());
                self.signature = crate::b64e::Base64(kp.sign(self.digest().as_bytes()).to_bytes());
            }
        }
    };
    proc_macro::TokenStream::from(expanded)
}

fn impl_digest(data: &Data) -> TokenStream {
    match *data {
        Data::Struct(ref data) => match data.fields {
            Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    // signature field should not be part of the signature
                    let sig = Some(Ident::new("signature", f.span()));
                    if *name == sig
                        && !f
                            .attrs
                            .iter()
                            .any(|attr| attr.path().get_ident().unwrap() == "digest_sig")
                    {
                        quote!()
                    } else {
                        quote_spanned! {f.span()=>
                            self.#name.digest(),
                        }
                    }
                });
                quote! { #(#recurse)* }
            }
            Fields::Unnamed(ref fields) => {
                let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let index = Index::from(i);
                    quote_spanned! {f.span()=>
                        self.#index.digest(),
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
