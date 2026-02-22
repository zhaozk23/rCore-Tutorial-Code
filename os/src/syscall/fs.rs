//! File and filesystem-related syscalls
use crate::config::PAGE_SIZE;
use crate::fs::inode::ROOT_INODE;
use crate::fs::{File, OpenFlags, Stat, open_file};
use crate::mm::{PageTable, UserBuffer, translated_byte_buffer, translated_str};
use crate::task::{current_task, current_user_token};

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_write", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    trace!("kernel:pid[{}] sys_read", current_task().unwrap().pid.0);
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        trace!("kernel: sys_read .. file.read");
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    trace!("kernel:pid[{}] sys_open", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let token = current_user_token();
    let mut path = translated_str(token, path);
    let inner = task.inner_exclusive_access();
    if let Some(real_path) = inner.links.get(&path) {
        path = real_path;
    }
    drop(inner);
    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();
        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        inner.names.insert(path.clone(), fd);
        if flags & OpenFlags::CREATE.bits() != 0 {
            inner.links.insert(path.clone(), path.clone());
        }
        let cnt = inner.links
            .values()
            .filter(|s|*s == path)
            .count();
        if cnt > 1 {
            inode.incr_nlink(cnt - 1);
        }
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    trace!("kernel:pid[{}] sys_close", current_task().unwrap().pid.0);
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if inner.fd_table[fd].is_none() {
        return -1;
    }
    inner.fd_table[fd].take();
    let key = inner.names
        .iter()
        .find_map(|(k,v)|{
            if v == fd {
                Some(k.clone())
            }else{
                None
            }
        });
    if let Some(key) = key {
        inner.names.remove(&key);
    }
    0
}

fn virtual_to_phys(virt: usize) -> *const u8 {
    let token = current_user_token();
    let vpn = virt / PAGE_SIZE;
    let offset = virt % PAGE_SIZE;
    let p_table = PageTable::from_token(token);
    let pte = p_table.translate(vpn.into()).unwrap();
    let ppn = pte.ppn().get_bytes_array().as_ptr();
    unsafe {
        ppn.add(offset)
    }
}

/// YOUR JOB: Implement fstat.
pub fn sys_fstat(fd: usize, _st: *mut Stat) -> isize {
    trace!(
        "kernel:pid[{}] sys_fstat",
        current_task().unwrap().pid.0
    );
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd > inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        drop(inner);
        let stat = file.stat();
        let st = unsafe {
            virtual_to_phys(_st as usize) as *mut Stat
        };
        unsafe {
            *st = stat;
        }
        0
    } else {
        -1
    }
}

/// YOUR JOB: Implement linkat.
pub fn sys_linkat(_old_name: *const u8, _new_name: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_linkat",
        current_task().unwrap().pid.0
    );
    let task = current_task().unwrap();
    let token = current_user_token();
    let old_name = translated_str(token, _old_name);
    let new_name = translated_str(token, _new_name);
    if old_name == new_name {
        return -1;
    }
    let mut inner = task.inner_exclusive_access();
    inner.links.insert(old_name, new_name);
    let fd = inner.names.get(&old_name).cloned();
    if fd.is_none() {
        return 0;
    }
    let fd = fd.unwrap();
    if fd > inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        drop(inner);
        file.incr_nlink(1);

        0
    } else {
        -1
    }
}

/// YOUR JOB: Implement unlinkat.
pub fn sys_unlinkat(_name: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_unlinkat",
        current_task().unwrap().pid.0
    );
    let task = current_task().unwrap();
    let token = current_user_token();
    let name = translated_str(token, _name);
    let mut inner = task.inner_exclusive_access();
    let path = inner.links.get(&name).cloned();
    if path.is_none() {
        return -1;
    }
    let path = path.unwrap();
    let fd = inner.names.get(&path).cloned();
    let res = inner.links.remove(&path);
    if let Some(fd) = fd {
        if let Some(file) = &inner.fd_table[fd] {
            file.decr_nlink(1);
        }
    }
    let cnt = inner.links
        .values()
        .filter(|s|*s == path)
        .count();
    if cnt == 0 {
        if let Some(node) = ROOT_INODE.find(name.as_str()) {
            node.clear();
        }
    }
    if res.is_some() {0} else {-1}
}
