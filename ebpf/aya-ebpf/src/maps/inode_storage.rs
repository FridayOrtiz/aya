use core::{marker::PhantomData, ptr};

use aya_ebpf_bindings::bindings::{BPF_F_NO_PREALLOC, BPF_LOCAL_STORAGE_GET_F_CREATE, bpf_map_type};
use aya_ebpf_cty::c_void;

use crate::{
    helpers::generated::{bpf_inode_storage_delete, bpf_inode_storage_get},
    maps::{MapDef, PinningType},
};

/// BPF inode storage map (`BPF_MAP_TYPE_INODE_STORAGE`).
///
/// Inode storage maps associate a value of type `V` with a kernel
/// `struct inode *`. The kernel allocates per-inode storage on demand and
/// reclaims it when the inode is evicted. Maps must be declared with
/// `BPF_F_NO_PREALLOC`; `max_entries` is ignored by the kernel.
#[repr(transparent)]
pub struct InodeStorage<V> {
    def: MapDef,
    _v: PhantomData<V>,
}

impl<V> crate::maps::private::Map for InodeStorage<V> {
    type Key = u32;
    type Value = V;
}

impl<V> InodeStorage<V> {
    pub const fn new() -> Self {
        Self::with_pinning(PinningType::None)
    }

    pub const fn pinned() -> Self {
        Self::with_pinning(PinningType::ByName)
    }

    const fn with_pinning(pinning: PinningType) -> Self {
        Self {
            def: MapDef::new::<u32, V>(
                bpf_map_type::BPF_MAP_TYPE_INODE_STORAGE,
                0,
                BPF_F_NO_PREALLOC,
                pinning,
            ),
            _v: PhantomData,
        }
    }

    /// Look up the storage entry for `inode`. Returns `None` if no entry
    /// exists. The pointer is valid for the duration of the current BPF
    /// program invocation.
    ///
    /// # Safety
    ///
    /// `inode` must be a valid kernel `struct inode *`.
    #[inline]
    pub unsafe fn get_ptr(&self, inode: *mut c_void) -> Option<*mut V> {
        let p = unsafe { bpf_inode_storage_get(self.def.as_ptr(), inode, ptr::null_mut(), 0) }
            .cast::<V>();
        if p.is_null() { None } else { Some(p) }
    }

    /// Look up the storage entry for `inode`, inserting a copy of `*value`
    /// if no entry exists yet. Returns `None` only on allocation failure.
    ///
    /// # Safety
    ///
    /// `inode` must be a valid kernel `struct inode *`. `value` must point
    /// to a fully-initialized `V`.
    #[inline]
    pub unsafe fn get_or_insert_ptr(&self, inode: *mut c_void, value: *mut V) -> Option<*mut V> {
        let p = unsafe {
            bpf_inode_storage_get(
                self.def.as_ptr(),
                inode,
                value.cast(),
                BPF_LOCAL_STORAGE_GET_F_CREATE as u64,
            )
        }
        .cast::<V>();
        if p.is_null() { None } else { Some(p) }
    }

    /// Remove the storage entry for `inode`.
    ///
    /// # Safety
    ///
    /// `inode` must be a valid kernel `struct inode *`.
    #[inline]
    pub unsafe fn delete(&self, inode: *mut c_void) -> Result<(), i32> {
        let ret = unsafe { bpf_inode_storage_delete(self.def.as_ptr(), inode) };
        if ret == 0 { Ok(()) } else { Err(ret) }
    }
}

impl<V> Default for InodeStorage<V> {
    fn default() -> Self {
        Self::new()
    }
}
