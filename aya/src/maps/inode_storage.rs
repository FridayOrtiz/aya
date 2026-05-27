//! An inode local storage map backed by `BPF_MAP_TYPE_INODE_STORAGE`.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    os::fd::AsRawFd,
};

use crate::{
    Pod,
    maps::{MapData, MapError, check_kv_size, hash_map},
};

/// An inode local storage map backed by `BPF_MAP_TYPE_INODE_STORAGE`.
///
/// This map type stores values that are owned by individual inodes. From
/// userspace the entries are keyed by a file descriptor whose inode the
/// kernel resolves; from BPF programs the entries are keyed by a trusted
/// `struct inode *` and accessed via [`bpf_inode_storage_get`].
///
/// [`bpf_inode_storage_get`]: https://elixir.bootlin.com/linux/v6.12/source/include/uapi/linux/bpf.h
#[doc(alias = "BPF_MAP_TYPE_INODE_STORAGE")]
#[derive(Debug)]
pub struct InodeStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> InodeStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<i32, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value associated with the inode behind `file`.
    pub fn get(&self, file: &impl AsRawFd, flags: u64) -> Result<V, MapError> {
        hash_map::get(self.inner.borrow(), &file.as_raw_fd(), flags)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> InodeStorage<T, V> {
    /// Creates or updates the value associated with the inode behind `file`.
    pub fn insert(
        &mut self,
        file: &impl AsRawFd,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(
            self.inner.borrow_mut(),
            &file.as_raw_fd(),
            value.borrow(),
            flags,
        )
    }

    /// Removes the storage associated with the inode behind `file`.
    pub fn remove(&mut self, file: &impl AsRawFd) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &file.as_raw_fd())
    }
}
