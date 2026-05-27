use core::ptr;

use aya_ebpf_bindings::bindings::{BPF_F_NO_PREALLOC, BPF_LOCAL_STORAGE_GET_F_CREATE};
use aya_ebpf_cty::c_void;

use crate::{
    btf_maps::btf_map_def,
    helpers::generated::{bpf_inode_storage_delete, bpf_inode_storage_get},
};

btf_map_def!(
    /// BTF-compatible BPF inode storage map.
    ///
    /// Inode storage associates a value of type `T` with a kernel
    /// `struct inode *`. The kernel allocates per-inode storage on demand
    /// and reclaims it when the inode is evicted. Map definitions must
    /// carry `BPF_F_NO_PREALLOC` and `max_entries: 0`.
    pub struct InodeStorage<T>,
    map_type: BPF_MAP_TYPE_INODE_STORAGE,
    max_entries: 0,
    map_flags: BPF_F_NO_PREALLOC as usize,
    key_type: i32,
    value_type: T,
);

impl<T> InodeStorage<T> {
    /// Look up the storage entry for `inode`. Returns `None` if no entry
    /// exists yet.
    ///
    /// # Safety
    ///
    /// `inode` must be a valid kernel `struct inode *`.
    #[inline(always)]
    pub unsafe fn get_ptr(&self, inode: *mut c_void) -> Option<*mut T> {
        let p = unsafe { bpf_inode_storage_get(self.as_ptr(), inode, ptr::null_mut(), 0) }
            .cast::<T>();
        if p.is_null() { None } else { Some(p) }
    }

    /// Look up the storage entry for `inode`, inserting a copy of `*value`
    /// if none exists. Returns `None` only on allocation failure.
    ///
    /// # Safety
    ///
    /// `inode` must be a valid kernel `struct inode *`. `value` must point
    /// to a fully-initialized `T`.
    #[inline(always)]
    pub unsafe fn get_or_insert_ptr(&self, inode: *mut c_void, value: *mut T) -> Option<*mut T> {
        let p = unsafe {
            bpf_inode_storage_get(
                self.as_ptr(),
                inode,
                value.cast(),
                BPF_LOCAL_STORAGE_GET_F_CREATE.into(),
            )
        }
        .cast::<T>();
        if p.is_null() { None } else { Some(p) }
    }

    /// Remove the storage entry for `inode`.
    ///
    /// # Safety
    ///
    /// `inode` must be a valid kernel `struct inode *`.
    #[inline(always)]
    pub unsafe fn delete(&self, inode: *mut c_void) -> Result<(), i32> {
        let ret = unsafe { bpf_inode_storage_delete(self.as_ptr(), inode) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}
