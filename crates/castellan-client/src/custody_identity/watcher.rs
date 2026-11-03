// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use super::*;

impl CustodyIdentity {
    /// Follow the lock broadcast on a second conversation: a Locked vault,
    /// or a djinn that went away, drops every held key (D11, D12).
    pub(super) fn watch(&self, endpoint: String, app: AppId, declaration: Option<AppDeclaration>) {
        let held = Arc::clone(&self.held);
        let locked = Arc::clone(&self.locked);
        let epoch = Arc::clone(&self.epoch);
        let stop = Arc::clone(&self.stop);
        let spawned = std::thread::Builder::new()
            .name(format!("custody-lock-{app}"))
            .spawn(move || {
                let drop_all = || {
                    invalidate_epoch(&locked, &epoch);
                    held.lock().unwrap_or_else(|e| e.into_inner()).clear();
                };
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                    drop_all(); return;
                };
                while !stop.load(Ordering::SeqCst) {
                    let opened = runtime.block_on(async {
                        tokio::select! {
                            _ = wait_stopped(&stop) => None,
                            result = tokio::time::timeout(Duration::from_secs(2), CustodyClient::open_at_with(&endpoint, app.clone(), declaration.clone())) => Some(result),
                        }
                    });
                    let mut client = match opened {
                        None => return,
                        Some(Ok(Ok(client))) => client,
                        Some(_) => {
                            drop_all();
                            runtime.block_on(async {
                                tokio::select! {
                                    _ = wait_stopped(&stop) => {},
                                    _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                                }
                            });
                            continue;
                        },
                    };
                    let mut seen = VaultLockView::Unlocked;
                    loop {
                        let changed = runtime.block_on(async {
                            tokio::select! {
                                _ = wait_stopped(&stop) => None,
                                result = client.watch_lock(seen) => Some(result),
                            }
                        });
                        match changed {
                            None => return,
                            Some(Ok(VaultLockView::Locked)) => {
                                drop_all(); seen = VaultLockView::Locked;
                            },
                            Some(Ok(VaultLockView::Unlocked)) => {
                                locked.store(false, Ordering::SeqCst); seen = VaultLockView::Unlocked;
                            },
                            Some(Err(_)) => { drop_all(); break; },
                        }
                    }
                }
            });
        match spawned {
            Ok(thread) => {
                *self.watch_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(thread)
            },
            Err(_) => {
                invalidate_epoch(&self.locked, &self.epoch);
                self.forget();
                tracing::warn!("custody lock watcher could not start; identity remains locked");
            },
        }
    }
}
