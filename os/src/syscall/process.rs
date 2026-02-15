//! Process management syscalls

use crate::{config::PAGE_SIZE, mm::{MapPermission, PageTable, VirtPageNum}, task::{TASK_MANAGER, change_program_brk, current_user_token, exit_current_and_run_next, suspend_current_and_run_next}, timer::get_time_us};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}
/// convert virtual address to physical address
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
    trace!("kernel: sys_get_time");
    let ts = unsafe {
        virtual_to_phys(_ts as usize) as *mut TimeVal
    };
    unsafe {
        *ts = TimeVal { sec: us / 1_000_000, usec: us % 1_000_000, }
    } 
    0
}
fn check_permission(addr: usize) -> Option<MapPermission> {
    let areas = TASK_MANAGER.get_tcb(id).memory_set.areas;
    let vpn: VirtPageNum = (addr / PAGE_SIZE).into();
    for area in areas {
        let vpn_range = area.vpn_range;
        if (vpn_range.get_start() <= vpn && vpn <= vpn_range.get_end()) {
            return Some(area.map_perm)
        }
    }
    None
}
/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(_trace_request: usize, _id: usize, _data: usize) -> isize {
    trace!("kernel: sys_trace");
    let id = virtual_to_phys(_id);
    let perm = check_permission(_id).unwrap();
    if (_trace_request == 0) {
        if (!perm.contains(MapPermission::U) || !perm.contains(MapPermission::R)){
            return -1;
        }
    }else if (_trace_request == 1) {
        if (!perm.contains(MapPermission::U) || !perm.contains(MapPermission::W)){
            return -1;
        }
    }
    match _trace_request {
        0 => unsafe {
            *id as isize
        },
        1 => unsafe {
            *(id as *mut u8) = _data as u8;
            0
        },
        2 => {
            TASK_MANAGER.get_syscall_count(_id) as isize
        }
        _ => -1,
    }
}

// YOUR JOB: Implement mmap.
pub fn sys_mmap(_start: usize, _len: usize, _port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if (_len == 0) {
        return 0;
    }
    if (_len % PAGE_SIZE != 0){
        return -1;
    }
    if (_port & 0x7 == 0 || _port & !0x7 != 0) {
        return -1;
    }
    -1
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(_start: usize, _len: usize) -> isize {
    trace!("kernel: sys_munmap");
    -1
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
