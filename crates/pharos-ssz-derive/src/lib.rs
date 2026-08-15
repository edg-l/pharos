//! Proc-macro derives for SSZ `Encode`, `Decode`, and `TreeHash`.
//!
//! Supports structs with named fields only. Enums and tuple structs are not
//! supported and will produce a compile error.
//!
//! All emitted type references use fully qualified paths (`::pharos_ssz::...`)
//! for macro hygiene (N1).
//!
//! # Container SSZ layout
//!
//! Field order = declaration order. Variable-size fields are detected by the
//! associated const `::pharos_ssz::Encode::IS_FIXED_SIZE`.
//!
//! Encode:
//! - Fixed region: for each field, write its fixed bytes (or a 4-byte offset
//!   placeholder for variable fields).
//! - Variable region: for each variable field, write its serialized bytes.
//!
//! Decode: use `::pharos_ssz::SszDecoder` to split the byte slice into per-field
//! slices, validate offsets, then decode each field.
//!
//! TreeHash: `TREE_HASH_TYPE = Container`. Root =
//! `merkleize(&[f1.tree_hash_root(), f2.tree_hash_root(), ...])`.
//!
//! # Field attributes
//!
//! `#[ssz(skip)]` — exclude a field from SSZ encoding and decoding. The field
//! must implement `Default`; it is set to `Default::default()` on decode.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

/// Structs with at least this many SSZ fields use `rayon::join` in `derive(TreeHash)`.
const PAR_TREE_HASH_FIELD_THRESHOLD: usize = 4;

// ── helper: extract named fields ──────────────────────────────────────────────

struct NamedField {
    ident: syn::Ident,
    ty: syn::Type,
    /// True when the field is annotated with `#[ssz(skip)]`.
    skip: bool,
}

/// Parse `#[ssz(skip)]` from a field's attributes. Returns `true` if found.
fn has_ssz_skip(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("ssz") {
            return false;
        }
        // Parse the contents as a parenthesised list of idents.
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn named_fields(input: &DeriveInput) -> syn::Result<Vec<NamedField>> {
    let fields = match &input.data {
        Data::Struct(s) => &s.fields,
        _ => {
            return Err(syn::Error::new_spanned(
                input,
                "SSZ derives only support structs with named fields",
            ));
        }
    };
    match fields {
        Fields::Named(named) => Ok(named
            .named
            .iter()
            .map(|f| NamedField {
                ident: f.ident.clone().expect("named field has ident"),
                ty: f.ty.clone(),
                skip: has_ssz_skip(&f.attrs),
            })
            .collect()),
        _ => Err(syn::Error::new_spanned(
            fields,
            "SSZ derives only support structs with named fields (not tuple or unit structs)",
        )),
    }
}

// ── #[derive(Encode)] ─────────────────────────────────────────────────────────

/// Derive macro for `::pharos_ssz::Encode`.
///
/// Generates `Encode` for a struct with named fields. The container is fixed-size
/// iff all fields are fixed-size.
///
/// # Generated code pattern (for a struct with fields a: u8, b: SomeVar, c: u32)
///
/// ```rust,ignore
/// impl ::pharos_ssz::Encode for MyStruct {
///     const IS_FIXED_SIZE: bool =
///         <u8 as ::pharos_ssz::Encode>::IS_FIXED_SIZE &&
///         <SomeVar as ::pharos_ssz::Encode>::IS_FIXED_SIZE &&
///         <u32 as ::pharos_ssz::Encode>::IS_FIXED_SIZE;
///
///     fn ssz_fixed_len() -> usize {
///         if <Self as ::pharos_ssz::Encode>::IS_FIXED_SIZE {
///             <u8 as ::pharos_ssz::Encode>::ssz_fixed_len()
///             + <SomeVar as ::pharos_ssz::Encode>::ssz_fixed_len()
///             + <u32 as ::pharos_ssz::Encode>::ssz_fixed_len()
///         } else {
///             ::pharos_ssz::BYTES_PER_LENGTH_OFFSET
///         }
///     }
///
///     fn ssz_bytes_len(&self) -> usize {
///         let mut len = 0usize;
///         len += <u8 as ::pharos_ssz::Encode>::ssz_fixed_len();
///         len += ::pharos_ssz::BYTES_PER_LENGTH_OFFSET + self.b.ssz_bytes_len();
///         len += <u32 as ::pharos_ssz::Encode>::ssz_fixed_len();
///         len
///     }
///
///     fn ssz_append(&self, buf: &mut Vec<u8>) { ... }
/// }
/// ```
#[proc_macro_derive(Encode, attributes(ssz))]
pub fn derive_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_encode_impl(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_encode_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let fields = named_fields(input)?;

    // Only non-skipped fields participate in SSZ encoding.
    let wire_fields: Vec<&NamedField> = fields.iter().filter(|f| !f.skip).collect();

    let field_types: Vec<&syn::Type> = wire_fields.iter().map(|f| &f.ty).collect();
    let field_idents: Vec<&syn::Ident> = wire_fields.iter().map(|f| &f.ident).collect();

    // IS_FIXED_SIZE = AND of all wire field IS_FIXED_SIZE consts.
    let is_fixed_size = if field_types.is_empty() {
        quote! { true }
    } else {
        let checks = field_types.iter().map(|ty| {
            quote! { <#ty as ::pharos_ssz::Encode>::IS_FIXED_SIZE }
        });
        // Each check is a bool const; fold with `&` to avoid `&&` separator issues.
        quote! { true #(&& #checks)* }
    };

    // ssz_fixed_len body: sum of all fields' fixed_len (used when IS_FIXED_SIZE is true).
    let fixed_len_stmts: Vec<TokenStream2> = field_types
        .iter()
        .map(|ty| quote! { len += <#ty as ::pharos_ssz::Encode>::ssz_fixed_len(); })
        .collect();

    // ssz_bytes_len: accumulate with explicit += statements to avoid if-expr concat issues.
    let bytes_len_stmts: Vec<TokenStream2> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(id, ty)| {
            quote! {
                if <#ty as ::pharos_ssz::Encode>::IS_FIXED_SIZE {
                    len += <#ty as ::pharos_ssz::Encode>::ssz_fixed_len();
                } else {
                    len += ::pharos_ssz::BYTES_PER_LENGTH_OFFSET;
                    len += self.#id.ssz_bytes_len();
                }
            }
        })
        .collect();

    // ssz_append: compute fixed region length, then two passes.
    let fixed_region_stmts: Vec<TokenStream2> = field_types
        .iter()
        .map(|ty| quote! { fixed_len += <#ty as ::pharos_ssz::Encode>::ssz_fixed_len(); })
        .collect();

    // First pass: write fixed fields inline; write offset placeholder for variable fields.
    let fixed_pass: Vec<TokenStream2> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(id, ty)| {
            quote! {
                if <#ty as ::pharos_ssz::Encode>::IS_FIXED_SIZE {
                    ::pharos_ssz::Encode::ssz_append(&self.#id, buf);
                } else {
                    buf.extend_from_slice(&(offset as u32).to_le_bytes());
                    offset += self.#id.ssz_bytes_len();
                }
            }
        })
        .collect();

    // Second pass: write variable field bodies.
    let var_pass: Vec<TokenStream2> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(id, ty)| {
            quote! {
                if !<#ty as ::pharos_ssz::Encode>::IS_FIXED_SIZE {
                    ::pharos_ssz::Encode::ssz_append(&self.#id, buf);
                }
            }
        })
        .collect();

    Ok(quote! {
        impl #impl_generics ::pharos_ssz::Encode for #name #ty_generics #where_clause {
            const IS_FIXED_SIZE: bool = #is_fixed_size;

            fn ssz_fixed_len() -> usize {
                if <Self as ::pharos_ssz::Encode>::IS_FIXED_SIZE {
                    let mut len: usize = 0;
                    #(#fixed_len_stmts)*
                    len
                } else {
                    ::pharos_ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn ssz_bytes_len(&self) -> usize {
                let mut len: usize = 0;
                #(#bytes_len_stmts)*
                len
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                // Compute the fixed region length first (sum of ssz_fixed_len for all fields).
                let mut fixed_len: usize = 0;
                #(#fixed_region_stmts)*
                // Running offset starts at the end of the fixed region.
                let mut offset: usize = fixed_len;
                // First pass: fixed fields written inline, variable fields get offset slots.
                #(#fixed_pass)*
                // Second pass: variable field bodies written in order.
                #(#var_pass)*
            }
        }
    })
}

// ── #[derive(Decode)] ─────────────────────────────────────────────────────────

/// Derive macro for `::pharos_ssz::Decode`.
///
/// Generates `Decode` for a struct with named fields using `SszDecoder` to
/// split the byte slice into per-field slices.
#[proc_macro_derive(Decode, attributes(ssz))]
pub fn derive_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_decode_impl(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_decode_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let fields = named_fields(input)?;

    // Separate wire fields (participate in SSZ) from skipped fields.
    let wire_fields: Vec<&NamedField> = fields.iter().filter(|f| !f.skip).collect();
    let skip_fields: Vec<&NamedField> = fields.iter().filter(|f| f.skip).collect();

    let field_types: Vec<&syn::Type> = wire_fields.iter().map(|f| &f.ty).collect();
    let field_idents: Vec<&syn::Ident> = wire_fields.iter().map(|f| &f.ident).collect();

    // IS_FIXED_SIZE: AND of all wire field IS_FIXED_SIZE.
    let is_fixed_size = if field_types.is_empty() {
        quote! { true }
    } else {
        let checks = field_types.iter().map(|ty| {
            quote! { <#ty as ::pharos_ssz::Decode>::IS_FIXED_SIZE }
        });
        quote! { true #(&& #checks)* }
    };

    // ssz_fixed_len body.
    let fixed_len_stmts: Vec<TokenStream2> = field_types
        .iter()
        .map(|ty| quote! { len += <#ty as ::pharos_ssz::Decode>::ssz_fixed_len(); })
        .collect();

    // Registration calls: register_type for fixed, register_anonymous_variable for variable.
    let register_calls: Vec<TokenStream2> = field_types
        .iter()
        .map(|ty| {
            quote! {
                if <#ty as ::pharos_ssz::Decode>::IS_FIXED_SIZE {
                    decoder.register_type::<#ty>()?;
                } else {
                    decoder.register_anonymous_variable_length_item::<#ty>()?;
                }
            }
        })
        .collect();

    // Decode calls: one per wire field.
    let decode_calls: Vec<TokenStream2> = field_idents
        .iter()
        .zip(field_types.iter())
        .map(|(id, ty)| {
            quote! {
                let #id: #ty = decoder.decode_next::<#ty>()?;
            }
        })
        .collect();

    // Skipped fields are initialised with Default::default().
    let skip_defaults: Vec<TokenStream2> = skip_fields
        .iter()
        .map(|f| {
            let id = &f.ident;
            let ty = &f.ty;
            quote! {
                let #id: #ty = Default::default();
            }
        })
        .collect();

    // Struct construction includes all fields (wire + skipped).
    let all_idents: Vec<&syn::Ident> = fields.iter().map(|f| &f.ident).collect();
    let construction = quote! {
        #name {
            #(#all_idents),*
        }
    };

    let decode_body = if field_idents.is_empty() {
        quote! {
            if !bytes.is_empty() {
                return Err(::pharos_ssz::SszError::ExtraBytes { extra: bytes.len() });
            }
            #(#skip_defaults)*
            Ok(#construction)
        }
    } else {
        quote! {
            let mut decoder = ::pharos_ssz::SszDecoder::new(bytes);
            #(#register_calls)*
            #(#decode_calls)*
            decoder.finish()?;
            #(#skip_defaults)*
            Ok(#construction)
        }
    };

    Ok(quote! {
        impl #impl_generics ::pharos_ssz::Decode for #name #ty_generics #where_clause {
            const IS_FIXED_SIZE: bool = #is_fixed_size;

            fn ssz_fixed_len() -> usize {
                if <Self as ::pharos_ssz::Decode>::IS_FIXED_SIZE {
                    let mut len: usize = 0;
                    #(#fixed_len_stmts)*
                    len
                } else {
                    ::pharos_ssz::BYTES_PER_LENGTH_OFFSET
                }
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ::pharos_ssz::SszError> {
                #decode_body
            }
        }
    })
}

// ── TreeHash helpers ─────────────────────────────────────────────────────────

/// Emit a balanced binary `::pharos_ssz::rayon::join` tree over `exprs`.
///
/// Each expression in `exprs` is wrapped in a closure that evaluates it and
/// returns a `::pharos_utils::Hash256`. The function returns a `TokenStream2`
/// that, when emitted, binds a pattern of `r0, r1, ..., rN` names and
/// finally evaluates to `&[r0, r1, ..., rN]` as a `&[::pharos_utils::Hash256]`.
///
/// Invariants:
/// - `exprs.len() >= 1`.
/// - For 1 expression, no `rayon::join` is emitted (closure only).
/// - For non-power-of-two counts, left half = ceil(N/2), right = floor(N/2).
///
/// The returned `TokenStream2` is a *block expression* that evaluates to
/// `[::pharos_utils::Hash256; N]` by binding intermediate let-patterns and
/// collecting into a final array.
fn build_balanced_join_tree(field_root_exprs: &[TokenStream2]) -> TokenStream2 {
    // Callers guarantee n >= PAR_TREE_HASH_FIELD_THRESHOLD (= 4).
    let n = field_root_exprs.len();

    // Assign each expression a variable name r0, r1, ...
    let var_names: Vec<proc_macro2::Ident> = (0..n)
        .map(|i| proc_macro2::Ident::new(&format!("__r{i}"), proc_macro2::Span::call_site()))
        .collect();

    // Build nested rayon::join pattern + binding block.
    let join_expr = build_join_expr(field_root_exprs, &var_names);

    // Collect the variables into the final array.
    let vars = &var_names;
    quote! {
        {
            #join_expr
            [#(#vars),*]
        }
    }
}

/// Recursively build nested `rayon::join` calls over slice `[lo, hi)` (index into
/// the original `exprs` / `names` slices).
///
/// Returns a `TokenStream2` that, when emitted as a statement, binds all
/// variables `names[lo..hi]` to their computed values.
fn build_join_expr(exprs: &[TokenStream2], names: &[proc_macro2::Ident]) -> TokenStream2 {
    let n = exprs.len();
    match n {
        0 => unreachable!("build_join_expr called with empty slice"),
        1 => {
            let name = &names[0];
            let expr = &exprs[0];
            quote! { let #name = #expr; }
        }
        _ => {
            // Left half = ceil(n/2), right half = floor(n/2).
            let mid = n.div_ceil(2);
            let (left_exprs, right_exprs) = exprs.split_at(mid);
            let (left_names, right_names) = names.split_at(mid);

            // Build sub-patterns: wrap each half in a tuple if > 1 element.
            let left_pat = join_pattern(left_names);
            let right_pat = join_pattern(right_names);

            // Closures for each half.
            let left_closure = build_join_closure(left_exprs, left_names);
            let right_closure = build_join_closure(right_exprs, right_names);

            quote! {
                let (#left_pat, #right_pat) = ::pharos_ssz::rayon::join(
                    #left_closure,
                    #right_closure,
                );
            }
        }
    }
}

/// Build a closure `|| { ... expr or nested join ... }` for a slice.
fn build_join_closure(exprs: &[TokenStream2], names: &[proc_macro2::Ident]) -> TokenStream2 {
    let n = exprs.len();
    match n {
        0 => unreachable!(),
        1 => {
            let expr = &exprs[0];
            quote! { || #expr }
        }
        _ => {
            let mid = n.div_ceil(2);
            let (left_exprs, right_exprs) = exprs.split_at(mid);
            let (left_names, right_names) = names.split_at(mid);

            let left_pat = join_pattern(left_names);
            let right_pat = join_pattern(right_names);

            let left_closure = build_join_closure(left_exprs, left_names);
            let right_closure = build_join_closure(right_exprs, right_names);

            quote! {
                || {
                    let (#left_pat, #right_pat) = ::pharos_ssz::rayon::join(
                        #left_closure,
                        #right_closure,
                    );
                    (#(#names),*)
                }
            }
        }
    }
}

/// Build a destructuring pattern from `names`.
/// 1 name → `name`, N names → `(n0, n1, ..., nN)`.
fn join_pattern(names: &[proc_macro2::Ident]) -> TokenStream2 {
    match names.len() {
        0 => unreachable!(),
        1 => quote! { #(#names)* },
        _ => quote! { (#(#names),*) },
    }
}

// ── #[derive(TreeHash)] ───────────────────────────────────────────────────────

/// Derive macro for `::pharos_ssz::TreeHash`.
///
/// Generates `TreeHash` for a struct with named fields.
///
/// - `TREE_HASH_TYPE = TreeHashType::Container`.
/// - `tree_hash_root` = `merkleize(&[f1.tree_hash_root(), f2.tree_hash_root(), ...])`.
/// - `tree_hash_packed_encoding` = `unreachable!()` (containers are never packed).
///
/// Fields annotated with `#[ssz(skip)]` are excluded from the Merkle root computation.
#[proc_macro_derive(TreeHash, attributes(ssz))]
pub fn derive_tree_hash(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match derive_tree_hash_impl(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn derive_tree_hash_impl(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let fields = named_fields(input)?;

    // Only non-skipped fields participate in Merkleization.
    let wire_fields: Vec<&NamedField> = fields.iter().filter(|f| !f.skip).collect();
    let field_idents: Vec<&syn::Ident> = wire_fields.iter().map(|f| &f.ident).collect();

    // Build the array of field roots.
    let field_root_exprs: Vec<TokenStream2> = field_idents
        .iter()
        .map(|id| {
            quote! { ::pharos_ssz::TreeHash::tree_hash_root(&self.#id) }
        })
        .collect();

    let tree_hash_root_body = if field_root_exprs.is_empty() {
        // Empty container: merkleize empty slice = zero hash.
        quote! {
            ::pharos_ssz::merkleize(&[])
        }
    } else if field_root_exprs.len() >= PAR_TREE_HASH_FIELD_THRESHOLD {
        // Parallel path: build a balanced rayon::join tree to compute field
        // roots in parallel, then merkleize the resulting array.
        let join_tree = build_balanced_join_tree(&field_root_exprs);
        quote! {
            let roots = #join_tree;
            ::pharos_ssz::merkleize(&roots)
        }
    } else {
        // Serial path for small structs (< PAR_TREE_HASH_FIELD_THRESHOLD fields).
        quote! {
            let roots: &[::pharos_utils::Hash256] = &[
                #(#field_root_exprs),*
            ];
            ::pharos_ssz::merkleize(roots)
        }
    };

    Ok(quote! {
        impl #impl_generics ::pharos_ssz::TreeHash for #name #ty_generics #where_clause {
            const TREE_HASH_TYPE: ::pharos_ssz::TreeHashType = ::pharos_ssz::TreeHashType::Container;

            fn tree_hash_root(&self) -> ::pharos_utils::Hash256 {
                #tree_hash_root_body
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("containers are not basic types and are never packed")
            }
        }
    })
}
