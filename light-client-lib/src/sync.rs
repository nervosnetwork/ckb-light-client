//! Cross-platform synchronization primitives.

#[cfg(not(target_arch = "wasm32"))]
pub use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(target_arch = "wasm32")]
pub use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[async_trait::async_trait]
pub trait RwLockExt<T> {
    async fn read_ext(
        &self,
    ) -> Result<RwLockReadGuard<'_, T>, std::sync::PoisonError<RwLockReadGuard<'_, T>>>;
    async fn write_ext(
        &self,
    ) -> Result<RwLockWriteGuard<'_, T>, std::sync::PoisonError<RwLockWriteGuard<'_, T>>>;
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl<T: Send + Sync> RwLockExt<T> for RwLock<T> {
    async fn read_ext(
        &self,
    ) -> Result<RwLockReadGuard<'_, T>, std::sync::PoisonError<RwLockReadGuard<'_, T>>> {
        tokio::task::block_in_place(|| self.read())
    }

    async fn write_ext(
        &self,
    ) -> Result<RwLockWriteGuard<'_, T>, std::sync::PoisonError<RwLockWriteGuard<'_, T>>> {
        tokio::task::block_in_place(|| self.write())
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait]
impl<T: Send + Sync> RwLockExt<T> for RwLock<T> {
    async fn read_ext(
        &self,
    ) -> Result<RwLockReadGuard<'_, T>, std::sync::PoisonError<RwLockReadGuard<'_, T>>> {
        Ok(self.read().await)
    }

    async fn write_ext(
        &self,
    ) -> Result<RwLockWriteGuard<'_, T>, std::sync::PoisonError<RwLockWriteGuard<'_, T>>> {
        Ok(self.write().await)
    }
}

#[async_trait::async_trait]
pub trait MutexExt<T> {
    async fn lock_ext(
        &self,
    ) -> Result<MutexGuard<'_, T>, std::sync::PoisonError<MutexGuard<'_, T>>>;
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait::async_trait]
impl<T: Send> MutexExt<T> for Mutex<T> {
    async fn lock_ext(
        &self,
    ) -> Result<MutexGuard<'_, T>, std::sync::PoisonError<MutexGuard<'_, T>>> {
        tokio::task::block_in_place(|| self.lock())
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait::async_trait]
impl<T: Send> MutexExt<T> for Mutex<T> {
    async fn lock_ext(
        &self,
    ) -> Result<MutexGuard<'_, T>, std::sync::PoisonError<MutexGuard<'_, T>>> {
        Ok(self.lock().await)
    }
}
