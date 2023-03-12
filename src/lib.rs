extern crate alloc;

use alloc::string::ToString;
use alloc::alloc::{alloc, dealloc, Layout};

use argon2::Argon2;
use argon2::Algorithm;
use argon2::Version;
use argon2::Params;
use argon2::PasswordHash;
use argon2::PasswordVerifier;

extern {
    pub fn panic(message: *mut u8, length: usize);
}

#[no_mangle]
pub unsafe fn allocate(size: usize) -> *mut u8 {
    let align = core::mem::align_of::<usize>();
    let layout = Layout::from_size_align_unchecked(size, align);
    alloc(layout)
}

#[no_mangle]
pub unsafe fn deallocate(ptr: *mut u8, size: usize) {
    let align = core::mem::align_of::<usize>();
    let layout = Layout::from_size_align_unchecked(size, align);
    dealloc(ptr, layout);
}

#[no_mangle]
pub unsafe fn hash(
    password_ptr: *const u8,
    password_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    algorithm: usize,
    memory_cost: u32,
    time_cost: u32,
    parallelism_cost: u32,
    output_length: usize,
    version: usize,
) -> *const u8 {
    let password = core::slice::from_raw_parts(password_ptr, password_len);
    let salt = core::slice::from_raw_parts(salt_ptr, salt_len);

    let algorithm = match algorithm {
        0 => Algorithm::Argon2d,
        1 => Algorithm::Argon2i,
        _ => Algorithm::Argon2id,
    };
    let version = match version {
        0x10 => Version::V0x10,
        _    => Version::V0x13,
    };

    let params = Params::new(
        1 << memory_cost,
        time_cost,
        parallelism_cost,
        Option::from(output_length)
    ).unwrap();
    
    let argon2 = Argon2::new(algorithm, version, params);
    let ptr = allocate(output_length);
    let out = core::slice::from_raw_parts_mut(ptr, output_length);

    argon2.hash_password_into(password, salt, out).unwrap();

    ptr
}

#[no_mangle]
pub unsafe fn verify(
    password_ptr: *const u8,
    password_len: usize,
    hash_ptr: *const u8,
    hash_len: usize,
) -> bool {
    let password = core::slice::from_raw_parts(password_ptr, password_len);
    let hash = core::slice::from_raw_parts(hash_ptr, hash_len);

    let argon2 = Argon2::default();
    let hash_instance = PasswordHash::new(core::str::from_utf8(hash).unwrap()).unwrap();
    let result = argon2.verify_password(password, &hash_instance);
    
    match result {
        Ok(()) => true,
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn init() {
    std::panic::set_hook(Box::new(|info| {
        let mut message = info.to_string();
        unsafe {
            panic(message.as_mut_ptr(), message.len());
        }
    }));
}
