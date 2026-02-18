//! Process management syscalls
use alloc::sync::Arc;

use crate::{
    config::PAGE_SIZE, loader::get_app_data_by_name, mm::{translated_refmut, translated_str}, task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next,
    }
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel:pid[{}] sys_yield", current_task().unwrap().pid.0);
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(data) = get_app_data_by_name(path.as_str()) {
        let task = current_task().unwrap();
        task.exec(data);
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    trace!("kernel::pid[{}] sys_waitpid [{}]", current_task().unwrap().pid.0, pid);
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
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
/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_get_time",
        current_task().unwrap().pid.0
    );
    let ts = unsafe {
        virtual_to_phys(_ts as usize) as *mut TimeVal
    };
    unsafe {
        *ts = TimeVal { sec: us / 1_000_000, usec: us % 1_000_000, }
    } 
    0
}


/// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_mmap",
        current_task().unwrap().pid.0
    );
    let mut memory_set = current_task().unwrap().get_memory_set();
    let len = (_len + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    let end = _start + len;
    let cur_areas = memory_set.areas;
    for area in cur_areas {
        let vpn_range = area.vpn_range;
        if (vpn_range.get_start().0 <= _start / PAGE_SIZE && _start / PAGE_SIZE <= vpn_range.get_end().0) {
            return -1;
        }
        if (vpn_range.get_start().0 <= end / PAGE_SIZE && end / PAGE_SIZE<= vpn_range.get_end().0){
            return -1;
        }
    }

    let mut permission = MapPermission::U;
    if (_port & 1 != 0) {
        permission |= MapPermission::R;
    }
    if (_port & 2 != 0) {
        permission |= MapPermission::W;
    }
    if (_port & 4 != 0) {
        permission |= MapPermission::X;
    }
    
    memory_set.insert_framed_area(_start.into(), end.into(), permission);
    0
}

/// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!(
        "kernel:pid[{}] sys_munmap",
        current_task().unwrap().pid.0
    );
    if (_start % PAGE_SIZE != 0) {
        return -1;
    }
    let mut memory_set = current_task().unwrap().get_memory_set();
    let len = (_len + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
    let end = _start + len;
    let mut found = false;
    let cur_areas = memory_set.areas;
    for area in cur_areas {
        let vpn_range = area.vpn_range;
        if (vpn_range.get_start().0 == _start / PAGE_SIZE && end / PAGE_SIZE == vpn_range.get_end().0) {
            found = true;
            break;
        }
    }
    if (!found) {
        return -1;
    }
    memory_set.unmap_area(_start.into(), end.into());
    0
}

/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// YOUR JOB: Implement spawn.
/// HINT: fork + exec =/= spawn
pub fn sys_spawn(_path: *const u8) -> isize {
    trace!(
        "kernel:pid[{}] sys_spawn NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1
}

// YOUR JOB: Set task priority.
pub fn sys_set_priority(_prio: isize) -> isize {
    trace!(
        "kernel:pid[{}] sys_set_priority NOT IMPLEMENTED",
        current_task().unwrap().pid.0
    );
    -1
}
