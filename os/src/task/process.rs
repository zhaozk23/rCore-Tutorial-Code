//! Implementation of  [`ProcessControlBlock`]

use super::id::RecycleAllocator;
use super::manager::insert_into_pid2process;
use super::TaskControlBlock;
use super::{add_task, SignalFlags};
use super::{pid_alloc, PidHandle};
use crate::fs::{File, Stdin, Stdout};
use crate::mm::{translated_refmut, MemorySet, KERNEL_SPACE};
use crate::sync::{Condvar, Mutex, Semaphore, UPSafeCell};
use crate::trap::{trap_handler, TrapContext};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefMut;

/// Process Control Block
pub struct ProcessControlBlock {
    /// immutable
    pub pid: PidHandle,
    /// mutable
    inner: UPSafeCell<ProcessControlBlockInner>,
}

/// Inner of Process Control Block
pub struct ProcessControlBlockInner {
    /// is zombie?
    pub is_zombie: bool,
    /// memory set(address space)
    pub memory_set: MemorySet,
    /// parent process
    pub parent: Option<Weak<ProcessControlBlock>>,
    /// children process
    pub children: Vec<Arc<ProcessControlBlock>>,
    /// exit code
    pub exit_code: i32,
    /// file descriptor table
    pub fd_table: Vec<Option<Arc<dyn File + Send + Sync>>>,
    /// signal flags
    pub signals: SignalFlags,
    /// tasks(also known as threads)
    pub tasks: Vec<Option<Arc<TaskControlBlock>>>,
    /// task resource allocator
    pub task_res_allocator: RecycleAllocator,
    /// mutex list
    pub mutex_list: Vec<Option<Arc<dyn Mutex>>>,
    /// semaphore list
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    /// condvar list
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
    /// enable deadlock check
    pub deadlock_detect_enabled: bool,
    /// mutex owner
    pub mutex_owner: Vec<Option<usize>>,
    /// semaphore allocation
    pub semaphore_alloc: Vec<Vec<usize>>,
    /// total semaphore count
    pub semaphore_count: Vec<usize>,
}

impl ProcessControlBlockInner {
    #[allow(unused)]
    /// get the address of app's page table
    pub fn get_user_token(&self) -> usize {
        self.memory_set.token()
    }
    /// allocate a new file descriptor
    pub fn alloc_fd(&mut self) -> usize {
        if let Some(fd) = (0..self.fd_table.len()).find(|fd| self.fd_table[*fd].is_none()) {
            fd
        } else {
            self.fd_table.push(None);
            self.fd_table.len() - 1
        }
    }
    /// allocate a new task id
    pub fn alloc_tid(&mut self) -> usize {
        let tid = self.task_res_allocator.alloc();
        for col in self.semaphore_alloc.iter_mut() {
            if col.len() <= tid {
                col.resize(tid + 1, 0);
            }
        }
        tid
    }
    /// deallocate a task id
    pub fn dealloc_tid(&mut self, tid: usize) {
        self.task_res_allocator.dealloc(tid);
        for col in self.semaphore_alloc.iter_mut() {
            if tid < col.len() {
                col[tid] = 0;
            }
        }
    }
    pub fn ensure_mutex_owner_len(&mut self) {
        while self.mutex_owner.len() < self.mutex_list.len() {
            self.mutex_owner.push(None);
        }
    }
    pub fn ensure_semaphore_alloc_len(&mut self) {
        let n = self.thread_count();
        while self.semaphore_alloc.len() < self.semaphore_list.len() {
            self.semaphore_alloc.push(vec![0; n]);
        }
        for col in self.semaphore_alloc.iter_mut() {
            if col.len() < n {
                col.resize(n, 0);
            }
        }
        while self.semaphore_count.len() < self.semaphore_list.len() {
            self.semaphore_count.push(0);
        }
    }
    /// the count of tasks(threads) in this process
    pub fn thread_count(&self) -> usize {
        self.tasks.len()
    }
    /// get a task with tid in this process
    pub fn get_task(&self, tid: usize) -> Arc<TaskControlBlock> {
        self.tasks[tid].as_ref().unwrap().clone()
    }
    pub fn will_deadlock_mutex(&self, req_tid: usize, req_mutex: usize) -> bool {
        let m = self.mutex_owner.len();
        let n = self.thread_count();
        if req_mutex >= m || req_tid >= n {
            return false;
        }
        // Available: 若 mutex 未被占有则 1，否则 0
        let mut work = vec![0usize; m];
        for j in 0..m {
            work[j] = if self.mutex_owner[j].is_none() { 1 } else { 0 };
        }
        // Allocation: allocation[i][j] = 1 当 owner[j] == Some(i)
        let mut allocation = vec![vec![0usize; m]; n];
        for j in 0..m {
            if let Some(owner) = self.mutex_owner[j] {
                if owner < n {
                    allocation[owner][j] = 1;
                }
            }
        }
        // Need: 默认 0，仅将当前请求视为 need[req_tid][req_mutex] = 1（简化）
        if allocation[req_tid][req_mutex] == 1 {
            // 若请求的是已持有的 mutex （重入或重复请求），视为不构成死锁
            return false;
        }
        let mut need = vec![vec![0usize; m]; n];
        need[req_tid][req_mutex] = 1;

        // Banker's safety algorithm
        let mut finish = vec![false; n];
        loop {
            let mut progressed = false;
            for i in 0..n {
                if !finish[i] {
                    let can_run = (0..m).all(|j| need[i][j] <= work[j]);
                    if can_run {
                        for j in 0..m {
                            work[j] += allocation[i][j];
                        }
                        finish[i] = true;
                        progressed = true;
                    }
                }
            }
            if !progressed { break; }
        }
        !finish.iter().all(|&x| x)
    }
    pub fn will_deadlock_semaphore(&self, req_tid: usize, sem_id: usize, req_cnt: usize) -> bool {
        let m = self.semaphore_alloc.len();
        let n = self.thread_count();
        if sem_id >= m || req_tid >= n {
            return false;
        }
        // Available[j] = total[j] - sum_{i} allocation[i][j]
        let mut work = vec![0usize; m];
        for j in 0..m {
            let total = self.semaphore_count.get(j).cloned().unwrap_or(0);
            let mut used = 0usize;
            if j < self.semaphore_alloc.len() {
                for i in 0..n {
                    if i < self.semaphore_alloc[j].len() {
                        used += self.semaphore_alloc[j][i];
                    }
                }
            }
            if total < used { work[j] = 0; } else { work[j] = total - used; }
        }
        // Allocation: allocation[i][j] = semaphore_alloc[j][i]
        let mut allocation = vec![vec![0usize; m]; n];
        for j in 0..m {
            if j < self.semaphore_alloc.len() {
                for i in 0..n {
                    if i < self.semaphore_alloc[j].len() {
                        allocation[i][j] = self.semaphore_alloc[j][i];
                    }
                }
            }
        }
        // Need: 默认 0，仅把当前请求设为 need[req_tid][sem_id] = req_cnt
        let mut need = vec![vec![0usize; m]; n];
        need[req_tid][sem_id] = req_cnt;

        // Banker's safety algorithm
        let mut finish = vec![false; n];
        loop {
            let mut progressed = false;
            for i in 0..n {
                if !finish[i] {
                    let can_run = (0..m).all(|j| need[i][j] <= work[j]);
                    if can_run {
                        for j in 0..m {
                            work[j] += allocation[i][j];
                        }
                        finish[i] = true;
                        progressed = true;
                    }
                }
            }
            if !progressed { break; }
        }
        !finish.iter().all(|&x| x)
    }
}

impl ProcessControlBlock {
    /// inner_exclusive_access
    pub fn inner_exclusive_access(&self) -> RefMut<'_, ProcessControlBlockInner> {
        self.inner.exclusive_access()
    }
    /// new process from elf file
    pub fn new(elf_data: &[u8]) -> Arc<Self> {
        trace!("kernel: ProcessControlBlock::new");
        // memory_set with elf program headers/trampoline/trap context/user stack
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        // allocate a pid
        let pid_handle = pid_alloc();
        let process = Arc::new(Self {
            pid: pid_handle,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: None,
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: vec![
                        // 0 -> stdin
                        Some(Arc::new(Stdin)),
                        // 1 -> stdout
                        Some(Arc::new(Stdout)),
                        // 2 -> stderr
                        Some(Arc::new(Stdout)),
                    ],
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    deadlock_detect_enabled: false,
                    mutex_owner: Vec::new(),
                    semaphore_alloc: Vec::new(),
                    semaphore_count: Vec::new(),
                })
            },
        });
        // create a main thread, we should allocate ustack and trap_cx here
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&process),
            ustack_base,
            true,
        ));
        // prepare trap_cx of main thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        let ustack_top = task_inner.res.as_ref().unwrap().ustack_top();
        let kstack_top = task.kstack.get_top();
        drop(task_inner);
        *trap_cx = TrapContext::app_init_context(
            entry_point,
            ustack_top,
            KERNEL_SPACE.exclusive_access().token(),
            kstack_top,
            trap_handler as usize,
        );
        // add main thread to the process
        let mut process_inner = process.inner_exclusive_access();
        process_inner.tasks.push(Some(Arc::clone(&task)));
        drop(process_inner);
        insert_into_pid2process(process.getpid(), Arc::clone(&process));
        // add main thread to scheduler
        add_task(task);
        process
    }

    /// Only support processes with a single thread.
    pub fn exec(self: &Arc<Self>, elf_data: &[u8], args: Vec<String>) {
        trace!("kernel: exec");
        assert_eq!(self.inner_exclusive_access().thread_count(), 1);
        // memory_set with elf program headers/trampoline/trap context/user stack
        trace!("kernel: exec .. MemorySet::from_elf");
        let (memory_set, ustack_base, entry_point) = MemorySet::from_elf(elf_data);
        let new_token = memory_set.token();
        // substitute memory_set
        trace!("kernel: exec .. substitute memory_set");
        self.inner_exclusive_access().memory_set = memory_set;
        // then we alloc user resource for main thread again
        // since memory_set has been changed
        trace!("kernel: exec .. alloc user resource for main thread again");
        let task = self.inner_exclusive_access().get_task(0);
        let mut task_inner = task.inner_exclusive_access();
        task_inner.res.as_mut().unwrap().ustack_base = ustack_base;
        task_inner.res.as_mut().unwrap().alloc_user_res();
        task_inner.trap_cx_ppn = task_inner.res.as_mut().unwrap().trap_cx_ppn();
        // push arguments on user stack
        trace!("kernel: exec .. push arguments on user stack");
        let mut user_sp = task_inner.res.as_mut().unwrap().ustack_top();
        user_sp -= (args.len() + 1) * core::mem::size_of::<usize>();
        let argv_base = user_sp;
        let mut argv: Vec<_> = (0..=args.len())
            .map(|arg| {
                translated_refmut(
                    new_token,
                    (argv_base + arg * core::mem::size_of::<usize>()) as *mut usize,
                )
            })
            .collect();
        *argv[args.len()] = 0;
        for i in 0..args.len() {
            user_sp -= args[i].len() + 1;
            *argv[i] = user_sp;
            let mut p = user_sp;
            for c in args[i].as_bytes() {
                *translated_refmut(new_token, p as *mut u8) = *c;
                p += 1;
            }
            *translated_refmut(new_token, p as *mut u8) = 0;
        }
        // make the user_sp aligned to 8B for k210 platform
        user_sp -= user_sp % core::mem::size_of::<usize>();
        // initialize trap_cx
        trace!("kernel: exec .. initialize trap_cx");
        let mut trap_cx = TrapContext::app_init_context(
            entry_point,
            user_sp,
            KERNEL_SPACE.exclusive_access().token(),
            task.kstack.get_top(),
            trap_handler as usize,
        );
        trap_cx.x[10] = args.len();
        trap_cx.x[11] = argv_base;
        *task_inner.get_trap_cx() = trap_cx;
    }

    /// Only support processes with a single thread.
    pub fn fork(self: &Arc<Self>) -> Arc<Self> {
        trace!("kernel: fork");
        let mut parent = self.inner_exclusive_access();
        assert_eq!(parent.thread_count(), 1);
        // clone parent's memory_set completely including trampoline/ustacks/trap_cxs
        let memory_set = MemorySet::from_existed_user(&parent.memory_set);
        // alloc a pid
        let pid = pid_alloc();
        // copy fd table
        let mut new_fd_table: Vec<Option<Arc<dyn File + Send + Sync>>> = Vec::new();
        for fd in parent.fd_table.iter() {
            if let Some(file) = fd {
                new_fd_table.push(Some(file.clone()));
            } else {
                new_fd_table.push(None);
            }
        }
        // create child process pcb
        let child = Arc::new(Self {
            pid,
            inner: unsafe {
                UPSafeCell::new(ProcessControlBlockInner {
                    is_zombie: false,
                    memory_set,
                    parent: Some(Arc::downgrade(self)),
                    children: Vec::new(),
                    exit_code: 0,
                    fd_table: new_fd_table,
                    signals: SignalFlags::empty(),
                    tasks: Vec::new(),
                    task_res_allocator: RecycleAllocator::new(),
                    mutex_list: Vec::new(),
                    semaphore_list: Vec::new(),
                    condvar_list: Vec::new(),
                    deadlock_detect_enabled: false,
                    mutex_owner: Vec::new(),
                    semaphore_alloc: Vec::new(),
                    semaphore_count: Vec::new(),
                })
            },
        });
        // add child
        parent.children.push(Arc::clone(&child));
        // create main thread of child process
        let task = Arc::new(TaskControlBlock::new(
            Arc::clone(&child),
            parent
                .get_task(0)
                .inner_exclusive_access()
                .res
                .as_ref()
                .unwrap()
                .ustack_base(),
            // here we do not allocate trap_cx or ustack again
            // but mention that we allocate a new kstack here
            false,
        ));
        // attach task to child process
        let mut child_inner = child.inner_exclusive_access();
        child_inner.tasks.push(Some(Arc::clone(&task)));
        drop(child_inner);
        // modify kstack_top in trap_cx of this thread
        let task_inner = task.inner_exclusive_access();
        let trap_cx = task_inner.get_trap_cx();
        trap_cx.kernel_sp = task.kstack.get_top();
        drop(task_inner);
        insert_into_pid2process(child.getpid(), Arc::clone(&child));
        // add this thread to scheduler
        add_task(task);
        child
    }
    /// get pid
    pub fn getpid(&self) -> usize {
        self.pid.0
    }
}
