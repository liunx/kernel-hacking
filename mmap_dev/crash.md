## 调试

### crash-01

首先通过 kdump 生成 vmcore-mm，然后通过 crash 工具进行调试。
```powershell
      KERNEL: x86_64/build/linux-6.8.12/vmlinux  [TAINTED]
    DUMPFILE: vmcore-mm  [PARTIAL DUMP]
        CPUS: 2
        DATE: Fri Dec 20 14:03:58 CST 2024
      UPTIME: 00:00:57
LOAD AVERAGE: 0.06, 0.02, 0.00
       TASKS: 60
    NODENAME: buildroot
     RELEASE: 6.8.12
     VERSION: #36 SMP PREEMPT_DYNAMIC Fri Dec 20 13:52:31 CST 2024
     MACHINE: x86_64  (1804 Mhz)
      MEMORY: 2 GB
       PANIC: "Oops: 0002 [#1] PREEMPT SMP NOPTI" (check log for details)
         PID: 71
     COMMAND: "syslogd"
        TASK: ffff8880044eae80  [THREAD_INFO: ffff8880044eae80]
         CPU: 0
       STATE: TASK_RUNNING (PANIC)
```
从 crash 的启动信息概览可以看到，panic 来自 syslogd 进程，我们可以检查以下他的内核堆栈情况。

```powershell
crash> set 71
    PID: 71
COMMAND: "syslogd"
   TASK: ffff8880044eae80  [THREAD_INFO: ffff8880044eae80]
    CPU: 0
  STATE: TASK_RUNNING (PANIC)
crash> bt
PID: 71       TASK: ffff8880044eae80  CPU: 0    COMMAND: "syslogd"
 #0 [ffffc9000022b7f0] machine_kexec at ffffffff8106ca09
 #1 [ffffc9000022b850] __crash_kexec at ffffffff81163fd3
 #2 [ffffc9000022b918] crash_kexec at ffffffff81165568
 #3 [ffffc9000022b928] oops_end at ffffffff8103791e
 #4 [ffffc9000022b950] page_fault_oops at ffffffff81076f86
 #5 [ffffc9000022b9d8] exc_page_fault at ffffffff819f15d4
 #6 [ffffc9000022baa8] __rmqueue_pcplist at ffffffff812f5833
 #7 [ffffc9000022bb68] get_page_from_freelist at ffffffff812f71a7
 #8 [ffffc9000022bc50] __alloc_pages at ffffffff812f941c
 #9 [ffffc9000022bcb8] shmem_get_folio_gfp at ffffffff812ab52d
#10 [ffffc9000022bd38] shmem_write_begin at ffffffff812ac04b
#11 [ffffc9000022bd70] generic_perform_write at ffffffff81288820
#12 [ffffc9000022bdf8] shmem_file_write_iter at ffffffff812a8ab0
#13 [ffffc9000022be30] vfs_write at ffffffff81327183
#14 [ffffc9000022bec8] ksys_write at ffffffff81327575
#15 [ffffc9000022bf08] __x64_sys_write at ffffffff8132761d
#16 [ffffc9000022bf18] x64_sys_call at ffffffff81002832
#17 [ffffc9000022bf28] do_syscall_64 at ffffffff819ecbc6
#18 [ffffc9000022bf50] entry_SYSCALL_64_after_hwframe at ffffffff81c00134
    RIP: 00007f3a54b8ec50  RSP: 00007ffe331d8e78  RFLAGS: 00000202
    RAX: ffffffffffffffda  RBX: 0000000000000003  RCX: 00007f3a54b8ec50
    RDX: 000000000000003d  RSI: 000055c51fc4c5e0  RDI: 0000000000000003
    RBP: 000055c51fc4c5e0   R8: 0000000000000040   R9: 00000000ffffffff
    R10: 0000000000000000  R11: 0000000000000202  R12: 000000000000003d
    R13: 00007f3a54a8d6c8  R14: 000055c51fc4c5e0  R15: 000055c51fc48368
    ORIG_RAX: 0000000000000001  CS: 0033  SS: 002b
crash> 
```
通过堆栈信息，我们可以确定他是 page_fault_oops，oops 发生在 __rmqueue_pcplist 函数中的某个位置，地址为 ffffffff812f5833，接下来让我们反汇编一探究竟。
```powershell
crash> dis __rmqueue_pcplist 
0xffffffff812f57b0 <__rmqueue_pcplist>: push   %rbp
0xffffffff812f57b1 <__rmqueue_pcplist+1>:       mov    %r8,%r10
0xffffffff812f57b4 <__rmqueue_pcplist+4>:       mov    %rsp,%rbp
0xffffffff812f57b7 <__rmqueue_pcplist+7>:       push   %r15
0xffffffff812f57b9 <__rmqueue_pcplist+9>:       push   %r14
0xffffffff812f57bb <__rmqueue_pcplist+11>:      mov    %esi,%r14d
0xffffffff812f57be <__rmqueue_pcplist+14>:      push   %r13
0xffffffff812f57c0 <__rmqueue_pcplist+16>:      mov    %r9,%r13 # r9 ==> struct list_head *list
0xffffffff812f57c3 <__rmqueue_pcplist+19>:      push   %r12
0xffffffff812f57c5 <__rmqueue_pcplist+21>:      push   %rbx
0xffffffff812f57c6 <__rmqueue_pcplist+22>:      mov    %rdi,%rbx
0xffffffff812f57c9 <__rmqueue_pcplist+25>:      sub    $0x68,%rsp
0xffffffff812f57cd <__rmqueue_pcplist+29>:      mov    %edx,-0x5c(%rbp)
0xffffffff812f57d0 <__rmqueue_pcplist+32>:      mov    %ecx,-0x60(%rbp)
0xffffffff812f57d3 <__rmqueue_pcplist+35>:      mov    %gs:0x28,%rax
0xffffffff812f57dc <__rmqueue_pcplist+44>:      mov    %rax,-0x30(%rbp)
0xffffffff812f57e0 <__rmqueue_pcplist+48>:      movslq %edx,%rax
0xffffffff812f57e3 <__rmqueue_pcplist+51>:      mov    %rax,%r12
0xffffffff812f57e6 <__rmqueue_pcplist+54>:      mov    %rax,-0x58(%rbp)
0xffffffff812f57ea <__rmqueue_pcplist+58>:      xor    %eax,%eax
0xffffffff812f57ec <__rmqueue_pcplist+60>:      shl    $0x4,%r12
0xffffffff812f57f0 <__rmqueue_pcplist+64>:      cmp    $0x2,%edx
0xffffffff812f57f3 <__rmqueue_pcplist+67>:      setle  %al
0xffffffff812f57f6 <__rmqueue_pcplist+70>:      mov    %eax,-0x90(%rbp)
0xffffffff812f57fc <__rmqueue_pcplist+76>:      mov    %esi,%eax
0xffffffff812f57fe <__rmqueue_pcplist+78>:      lea    (%rax,%rax,8),%rax
0xffffffff812f5802 <__rmqueue_pcplist+82>:      lea    0xc0(%r12,%rax,8),%rax
0xffffffff812f580a <__rmqueue_pcplist+90>:      add    %rdi,%rax
0xffffffff812f580d <__rmqueue_pcplist+93>:      mov    %rax,-0x48(%rbp)
0xffffffff812f5811 <__rmqueue_pcplist+97>:      mov    0x0(%r13),%rax
0xffffffff812f5815 <__rmqueue_pcplist+101>:     cmp    %rax,%r13
0xffffffff812f5818 <__rmqueue_pcplist+104>:     je     0xffffffff812f588a <__rmqueue_pcplist+218>
0xffffffff812f581a <__rmqueue_pcplist+106>:     movabs $0xdead000000000100,%rdi
0xffffffff812f5824 <__rmqueue_pcplist+116>:     mov    0x0(%r13),%rax
0xffffffff812f5828 <__rmqueue_pcplist+120>:     mov    (%rax),%rcx
0xffffffff812f582b <__rmqueue_pcplist+123>:     mov    0x8(%rax),%rdx
0xffffffff812f582f <__rmqueue_pcplist+127>:     lea    -0x8(%rax),%rsi
0xffffffff812f5833 <__rmqueue_pcplist+131>:     mov    %rdx,0x8(%rcx) # <== crashed here!!!
0xffffffff812f5837 <__rmqueue_pcplist+135>:     mov    %rcx,(%rdx)
0xffffffff812f583a <__rmqueue_pcplist+138>:     mov    %r14d,%ecx
0xffffffff812f583d <__rmqueue_pcplist+141>:     mov    $0x1,%edx
0xffffffff812f5842 <__rmqueue_pcplist+146>:     shl    %cl,%edx
0xffffffff812f5844 <__rmqueue_pcplist+148>:     mov    0x1b9bcc6(%rip),%ecx        # 0xffffffff82e91510 <check_pages_enabled>
0xffffffff812f584a <__rmqueue_pcplist+154>:     mov    %rdi,(%rax)
0xffffffff812f584d <__rmqueue_pcplist+157>:     add    $0x22,%rdi
0xffffffff812f5851 <__rmqueue_pcplist+161>:     mov    %rdi,0x8(%rax)
0xffffffff812f5855 <__rmqueue_pcplist+165>:     sub    %edx,0x4(%r10)
0xffffffff812f5859 <__rmqueue_pcplist+169>:     test   %ecx,%ecx
0xffffffff812f585b <__rmqueue_pcplist+171>:     jg     0xffffffff812f5d9e <__rmqueue_pcplist+1518>
0xffffffff812f5861 <__rmqueue_pcplist+177>:     mov    -0x30(%rbp),%rax
0xffffffff812f5865 <__rmqueue_pcplist+181>:     sub    %gs:0x28,%rax
0xffffffff812f586e <__rmqueue_pcplist+190>:     jne    0xffffffff812f5e76 <__rmqueue_pcplist+1734>
0xffffffff812f5874 <__rmqueue_pcplist+196>:     add    $0x68,%rsp
0xffffffff812f5878 <__rmqueue_pcplist+200>:     mov    %rsi,%rax
0xffffffff812f587b <__rmqueue_pcplist+203>:     pop    %rbx
0xffffffff812f587c <__rmqueue_pcplist+204>:     pop    %r12
0xffffffff812f587e <__rmqueue_pcplist+206>:     pop    %r13
0xffffffff812f5880 <__rmqueue_pcplist+208>:     pop    %r14
0xffffffff812f5882 <__rmqueue_pcplist+210>:     pop    %r15
0xffffffff812f5884 <__rmqueue_pcplist+212>:     pop    %rbp
0xffffffff812f5885 <__rmqueue_pcplist+213>:     ret    
```
r9 寄存器存放着 __rmqueue_pcplist 的第六个参数 `struct list_head *list`，这说明我们可能是在操作链表的时候出了问题，结合着 dmesg 信息：

```powershell
crash> log
[...]
[   57.655884] #PF: supervisor write access in kernel mode
[   57.656568] #PF: error_code(0x0002) - not-present page
[   57.657245] PGD 0 P4D 0 
[   57.657476] Oops: 0002 [#1] PREEMPT SMP NOPTI
[   57.658010] CPU: 0 PID: 71 Comm: syslogd Kdump: loaded Tainted: G           O       6.8.12 #36
[   57.659280] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
[   57.661124] RIP: 0010:__rmqueue_pcplist+0x83/0x6d0
[   57.661830] Code: 00 48 01 f8 48 89 45 b8 49 8b 45 00 49 39 c5 74 70 48 bf 00 01 00 00 00 00 ad de 49 8b 45 00 48 8b 08 48 8b 50 08 48 8d 70 f8 <48> 89 51 08 48 89 0a 44 89 f1 ba 01 00 00 00 d3 e2 8b 0d c6 bc b9
[   57.664949] RSP: 0018:ffffc9000022bad0 EFLAGS: 00010297
[   57.665628] RAX: ffffea0001ff5cc8 RBX: ffffffff82b7a3c0 RCX: 0000000000000000
[   57.666610] RDX: dead000000000122 RSI: ffffea0001ff5cc0 RDI: dead000000000100
[   57.667596] RBP: ffffc9000022bb60 R08: ffff88807fc32680 R09: ffff88807fc326b0
[   57.668537] R10: ffff88807fc32680 R11: 0000000000000000 R12: 0000000000000010
[   57.669353] R13: ffff88807fc326b0 R14: 0000000000000000 R15: 000000000004c68d
[   57.670179] FS:  00007f3a54a8d740(0000) GS:ffff88807fc00000(0000) knlGS:0000000000000000
[   57.671041] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   57.671518] CR2: 0000000000000008 CR3: 0000000003680000 CR4: 0000000000750ef0
[   57.672131] PKRU: 55555554
[   57.672298] Call Trace:
[   57.672440]  <TASK>
[   57.672546]  ? show_regs+0x69/0x80
[   57.672797]  ? __die+0x28/0x70
[   57.672995]  ? page_fault_oops+0x182/0x4b0
[   57.673308]  ? check_preempt_wakeup_fair+0xda/0xf0
[   57.673695]  ? exc_page_fault+0x3d4/0x740
[   57.673996]  ? asm_exc_page_fault+0x2b/0x30
[   57.674251]  ? __rmqueue_pcplist+0x83/0x6d0
[   57.674484]  ? newidle_balance+0x2d7/0x4a0
[   57.674714]  get_page_from_freelist+0x207/0xfa0
[   57.674972]  __alloc_pages+0x12c/0x2c0
[   57.675170]  shmem_get_folio_gfp+0x19d/0x530
[   57.675410]  ? preempt_count_sub+0x50/0x80
[   57.675635]  shmem_write_begin+0x5b/0xc0
[   57.675846]  generic_perform_write+0xd0/0x220
[   57.676094]  shmem_file_write_iter+0x90/0xa0
[   57.676333]  vfs_write+0x273/0x4a0
[   57.676513]  ksys_write+0x75/0xf0
[   57.676678]  __x64_sys_write+0x1d/0x30
[   57.676874]  x64_sys_call+0x82/0x1d00
[   57.677064]  do_syscall_64+0x86/0x1a0
[   57.677240]  entry_SYSCALL_64_after_hwframe+0x78/0x80
[   57.677472] RIP: 0033:0x7f3a54b8ec50
[   57.677619] Code: d1 0d 00 64 c7 00 16 00 00 00 b8 ff ff ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 80 3d f9 53 0e 00 00 74 17 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 58 c3 0f 1f 80 00 00 00 00 48 83 ec 28 48 89
[   57.678660] RSP: 002b:00007ffe331d8e78 EFLAGS: 00000202 ORIG_RAX: 0000000000000001
[   57.679044] RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00007f3a54b8ec50
[   57.679399] RDX: 000000000000003d RSI: 000055c51fc4c5e0 RDI: 0000000000000003
[   57.679754] RBP: 000055c51fc4c5e0 R08: 0000000000000040 R09: 00000000ffffffff
[   57.680109] R10: 0000000000000000 R11: 0000000000000202 R12: 000000000000003d
[   57.680451] R13: 00007f3a54a8d6c8 R14: 000055c51fc4c5e0 R15: 000055c51fc48368
[   57.680804]  </TASK>
[   57.680869] Modules linked in: mmap_dev(O)
[   57.681047] CR2: 0000000000000008
```
空指针引用，那么可以肯定我们在链表操作的时候引用了已经释放了的对象，为了进一步确认，我们继续深入汇编代码一探究竟：
```powershell
crash> dis exec_page_fault
0xffffffff819f1200 <exc_page_fault>:    nopw   (%rax)
0xffffffff819f1204 <exc_page_fault+4>:  push   %rbp
0xffffffff819f1205 <exc_page_fault+5>:  mov    %rsp,%rbp
0xffffffff819f1208 <exc_page_fault+8>:  push   %r15
0xffffffff819f120a <exc_page_fault+10>: push   %r14
0xffffffff819f120c <exc_page_fault+12>: push   %r13
0xffffffff819f120e <exc_page_fault+14>: push   %r12
0xffffffff819f1210 <exc_page_fault+16>: mov    %rsi,%r12
0xffffffff819f1213 <exc_page_fault+19>: push   %rbx
0xffffffff819f1214 <exc_page_fault+20>: mov    %rdi,%rbx
0xffffffff819f1217 <exc_page_fault+23>: sub    $0x10,%rsp
0xffffffff819f121b <exc_page_fault+27>: mov    %cr2,%r13
0xffffffff819f121f <exc_page_fault+31>: mov    %gs:0x2d880,%rax
0xffffffff819f1228 <exc_page_fault+40>: mov    0x400(%rax),%rax
0xffffffff819f122f <exc_page_fault+47>: prefetchw 0xa0(%rax)
0xffffffff819f1236 <exc_page_fault+54>: mov    0x1466e04(%rip),%eax        # 0xffffffff82e58040 <kvm_async_pf_enabled>
0xffffffff819f123c <exc_page_fault+60>: test   %eax,%eax
0xffffffff819f123e <exc_page_fault+62>: jg     0xffffffff819f14d1 <exc_page_fault+721>
0xffffffff819f1244 <exc_page_fault+68>: mov    %rbx,%rdi
0xffffffff819f1247 <exc_page_fault+71>: call   0xffffffff819f1fa0 <irqentry_enter>
0xffffffff819f124c <exc_page_fault+76>: mov    %al,-0x29(%rbp)
0xffffffff819f124f <exc_page_fault+79>: mov    0x146adbb(%rip),%eax        # 0xffffffff82e5c010 <trace_pagefault_key>
0xffffffff819f1255 <exc_page_fault+85>: test   %eax,%eax
0xffffffff819f1257 <exc_page_fault+87>: jg     0xffffffff819f14fc <exc_page_fault+764>
0xffffffff819f125d <exc_page_fault+93>: mov    0x146b6fd(%rip),%ecx        # 0xffffffff82e5c960 <kmmio_count>
0xffffffff819f1263 <exc_page_fault+99>: test   %ecx,%ecx
...
```
书接上文，我们为啥要反汇编 dis_exec_page_fault，因为我们要找到 r13 寄存器存储在栈上的值，然后顺藤摸瓜，确定 crash 那一刻 rax、rdx、rcx 寄存器的值：
```powershell
...
0xffffffff812f580d <__rmqueue_pcplist+93>:      mov    %rax,-0x48(%rbp)
0xffffffff812f5811 <__rmqueue_pcplist+97>:      mov    0x0(%r13),%rax
0xffffffff812f5815 <__rmqueue_pcplist+101>:     cmp    %rax,%r13
0xffffffff812f5818 <__rmqueue_pcplist+104>:     je     0xffffffff812f588a <__rmqueue_pcplist+218>
0xffffffff812f581a <__rmqueue_pcplist+106>:     movabs $0xdead000000000100,%rdi
0xffffffff812f5824 <__rmqueue_pcplist+116>:     mov    0x0(%r13),%rax
0xffffffff812f5828 <__rmqueue_pcplist+120>:     mov    (%rax),%rcx
0xffffffff812f582b <__rmqueue_pcplist+123>:     mov    0x8(%rax),%rdx
0xffffffff812f582f <__rmqueue_pcplist+127>:     lea    -0x8(%rax),%rsi
0xffffffff812f5833 <__rmqueue_pcplist+131>:     mov    %rdx,0x8(%rcx) # <== crashed here!!!
0xffffffff812f5837 <__rmqueue_pcplist+135>:     mov    %rcx,(%rdx)
...
```
下面让我找到 rbp 寄存器的值：
```powershell
crash> bt -f
PID: 71       TASK: ffff8880044eae80  CPU: 0    COMMAND: "syslogd"
 #0 [ffffc9000022b7f0] machine_kexec at ffffffff8106ca09
    ffffc9000022b7f8: 0000000000000046 0000000000000000 
    ffffc9000022b808: 000000005f003000 ffff88805f003000 
    ffffc9000022b818: 000000005f002000 0000000000000000 
    ffffc9000022b828: f60af2f909041500 ffffc9000022b858 
    ffffc9000022b838: ffffc9000022ba28 0000000000000046 
    ffffc9000022b848: ffffc9000022b910 ffffffff81163fd3 
 #1 [ffffc9000022b850] __crash_kexec at ffffffff81163fd3
    ffffc9000022b858: 000000000004c68d 0000000000000000 
    ffffc9000022b868: ffff88807fc326b0 0000000000000010 
    ffffc9000022b878: ffffc9000022bb60 ffffffff82b7a3c0 
    ffffc9000022b888: 0000000000000000 ffff88807fc32680 
    ffffc9000022b898: ffff88807fc326b0 ffff88807fc32680 
    ffffc9000022b8a8: ffffea0001ff5cc8 0000000000000000 
    ffffc9000022b8b8: dead000000000122 ffffea0001ff5cc0 
    ffffc9000022b8c8: dead000000000100 ffffffffffffffff 
    ffffc9000022b8d8: ffffffff812f5833 0000000000000010 
    ffffc9000022b8e8: 0000000000010297 ffffc9000022bad0 
    ffffc9000022b8f8: 0000000000000018 f60af2f909041500 
    ffffc9000022b908: 0000000000000009 ffffc9000022b920 
    ffffc9000022b918: ffffffff81165568 
 #2 [ffffc9000022b918] crash_kexec at ffffffff81165568
    ffffc9000022b920: ffffc9000022b948 ffffffff8103791e 
 #3 [ffffc9000022b928] oops_end at ffffffff8103791e
    ffffc9000022b930: 0000000000000009 ffffc9000022ba28 
    ffffc9000022b940: 0000000000000008 ffffc9000022b9d0 
    ffffc9000022b950: ffffffff81076f86 
 #4 [ffffc9000022b950] page_fault_oops at ffffffff81076f86
    ffffc9000022b958: ffff88807fd2e1c0 ffffc9000022b998 
    ffffc9000022b968: ffffffff810da2ba ffff8880036bdd00 
    ffffc9000022b978: ffff88807fd2e0c0 0000000000000000 
    ffffc9000022b988: 0000000000000000 0000000000000000 
    ffffc9000022b998: 0000000000000000 f60af2f909041500 
    ffffc9000022b9a8: ffffc9000022ba28 0000000000000002 
    ffffc9000022b9b8: 0000000000000008 0000000000000000 
    ffffc9000022b9c8: ffff888003449e00 ffffc9000022ba18 
    ffffc9000022b9d8: ffffffff819f15d4 
 #5 [ffffc9000022b9d8] exc_page_fault at ffffffff819f15d4
    ffffc9000022b9e0: 000000000002e0c0 00ff888003701540 
    ffffc9000022b9f0: 0000000000000000 0000000000000000 
    ffffc9000022ba00: 0000000000000000 0000000000000000 
    ffffc9000022ba10: 0000000000000000 ffffc9000022ba29 
    ffffc9000022ba20: ffffffff81c0136b 000000000004c68d 
    ffffc9000022ba30: 0000000000000000 ffff88807fc326b0 
    ffffc9000022ba40: 0000000000000010 ffffc9000022bb60 
    ffffc9000022ba50: ffffffff82b7a3c0 0000000000000000 
    ffffc9000022ba60: ffff88807fc32680 ffff88807fc326b0 
    ffffc9000022ba70: ffff88807fc32680 ffffea0001ff5cc8 
    ffffc9000022ba80: 0000000000000000 dead000000000122 
    ffffc9000022ba90: ffffea0001ff5cc0 dead000000000100 
    ffffc9000022baa0: ffffffffffffffff ffffffff812f5833 
 #6 [ffffc9000022baa8] __rmqueue_pcplist at ffffffff812f5833
    ffffc9000022bab0: 0000000000000010 0000000000010297 
    ffffc9000022bac0: ffffc9000022bad0 0000000000000018 
    ffffc9000022bad0: ffff888000000001 ffffc9000022bb30 
    ffffc9000022bae0: ffffc9000022bb48 ffffffff810df5e7 
    ffffc9000022baf0: ffff888000000001 ffffc9000022bb98 
    ffffc9000022bb00: 0000000100000801 0000000000000001 
    ffffc9000022bb10: 0000000000000000 ffffffff82b7a490 
    ffffc9000022bb20: ffff88807fc2e0c0 0000000000000000 
    ffffc9000022bb30: f60af2f909041500 ffff88807fc32680 
    ffffc9000022bb40: ffffffff82b7a3c0 ffffc9000022bc58 
    ffffc9000022bb50: 0000000000000000 000000000004c68d 
    ffffc9000022bb60: ffffc9000022bc48 ffffffff812f71a7 
 #7 [ffffc9000022bb68] get_page_from_freelist at ffffffff812f71a7
    ffffc9000022bb70: 0000000009041500 00100cca00000000 
    ffffc9000022bb80: 00000000000000f0 0000000000000001 
    ffffc9000022bb90: 0000000000000000 0000000000000000 
    ffffc9000022bba0: 0000000000000000 ffffffff82b7a798 
    ffffc9000022bbb0: 0000000000000000 0000000100100005 
    ffffc9000022bbc0: 01000001038d1e6b ffffffffffffffff 
    ffffc9000022bbd0: ffffffff82b7b200 0000000000000000 
...
```

### crash-02
首先看一下 dmesg 信息：
```powershell
crash> log
...
[   52.211013] BUG: kernel NULL pointer dereference, address: 0000000000000008
[   52.211356] #PF: supervisor write access in kernel mode
[   52.211602] #PF: error_code(0x0002) - not-present page
[   52.211837] PGD 0 P4D 0 
[   52.211923] Oops: 0002 [#1] PREEMPT SMP NOPTI
[   52.212114] CPU: 1 PID: 22 Comm: ksoftirqd/1 Kdump: loaded Tainted: G           O       6.8.12 #36
[   52.212580] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014
[   52.213180] RIP: 0010:__page_cache_release+0xac/0x210
[   52.213431] Code: 52 01 00 00 48 8b 03 48 8b 13 48 c1 e8 13 48 c1 ea 08 83 e0 01 83 e2 01 83 f0 01 0f b6 c0 44 8d 3c 42 48 8b 43 10 48 8b 53 08 <48> 89 42 08 48 89 10 48 b8 00 01 00 00 00 00 ad de 48 89 43 08 48
[   52.214471] RSP: 0018:ffffc900000c3cc8 EFLAGS: 00010046
[   52.214712] RAX: dead000000000122 RBX: ffffea00001e9440 RCX: 0000000000000317
[   52.215070] RDX: 0000000000000000 RSI: ffffffff811a890d RDI: 0000000000000001
[   52.215801] RBP: ffffc900000c3d10 R08: 0000000000000000 R09: 0000000000005ac5
[   52.216380] R10: 0000000000000c12 R11: 0000000000000000 R12: ffff88800360b800
[   52.216769] R13: ffff88807fd2ec80 R14: ffffc900000c3da0 R15: 0000000000000001
[   52.217137] FS:  0000000000000000(0000) GS:ffff88807fd00000(0000) knlGS:0000000000000000
[   52.217550] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   52.217820] CR2: 0000000000000008 CR3: 0000000004b24000 CR4: 0000000000750ef0
[   52.218176] PKRU: 55555554
[   52.218269] Call Trace:
[   52.218351]  <TASK>
[   52.218412]  ? show_regs+0x69/0x80
[   52.218597]  ? __die+0x28/0x70
[   52.218712]  ? page_fault_oops+0x182/0x4b0
[   52.218892]  ? check_preempt_wakeup_fair+0x9d/0xf0
[   52.219116]  ? exc_page_fault+0x3d4/0x740
[   52.219295]  ? asm_exc_page_fault+0x2b/0x30
[   52.219483]  ? trace_hardirqs_off+0x1d/0x30
[   52.219673]  ? __page_cache_release+0xac/0x210
[   52.219869]  ? __page_cache_release+0x75/0x210
[   52.220066]  ? free_unref_page+0x132/0x150
[   52.220243]  __folio_put+0x1d/0x60
[   52.220379]  free_page_and_swap_cache+0x3c/0x50
[   52.220585]  tlb_remove_table_rcu+0x2c/0x50
[   52.220768]  rcu_do_batch+0x204/0x8a0
[   52.220923]  ? update_load_avg+0x61/0x310
[   52.221093]  rcu_core+0x199/0x4d0
[   52.221223]  rcu_core_si+0x12/0x20
[   52.221360]  handle_softirqs+0x10c/0x3c0
[   52.221537]  ? __pfx_smpboot_thread_fn+0x10/0x10
[   52.221749]  run_ksoftirqd+0x38/0x50
[   52.221904]  smpboot_thread_fn+0x188/0x230
[   52.222078]  kthread+0x102/0x130
[   52.222216]  ? __pfx_kthread+0x10/0x10
[   52.222371]  ret_from_fork+0x3e/0x60
[   52.222534]  ? __pfx_kthread+0x10/0x10
[   52.222695]  ret_from_fork_asm+0x1b/0x30
[   52.222874]  </TASK>
[   52.222948] Modules linked in: mmap_dev(O)
[   52.223144] CR2: 0000000000000008
```
很明显，空指针。

```powershell
crash> dis __page_cache_release
0xffffffff81299c70 <__page_cache_release>:      nopl   0x0(%rax,%rax,1) [FTRACE NOP]
0xffffffff81299c75 <__page_cache_release+5>:    push   %rbp
0xffffffff81299c76 <__page_cache_release+6>:    mov    %rsp,%rbp
0xffffffff81299c79 <__page_cache_release+9>:    push   %r15
0xffffffff81299c7b <__page_cache_release+11>:   push   %r14
0xffffffff81299c7d <__page_cache_release+13>:   push   %r13
0xffffffff81299c7f <__page_cache_release+15>:   push   %r12
0xffffffff81299c81 <__page_cache_release+17>:   push   %rbx
0xffffffff81299c82 <__page_cache_release+18>:   sub    $0x20,%rsp
0xffffffff81299c86 <__page_cache_release+22>:   mov    %gs:0x28,%rbx
0xffffffff81299c8f <__page_cache_release+31>:   mov    %rbx,-0x30(%rbp)
0xffffffff81299c93 <__page_cache_release+35>:   mov    %rdi,%rbx
0xffffffff81299c96 <__page_cache_release+38>:   mov    (%rdi),%rax
0xffffffff81299c99 <__page_cache_release+41>:   test   $0x20,%al
0xffffffff81299c9b <__page_cache_release+43>:   jne    0xffffffff81299cd1 <__page_cache_release+97>
0xffffffff81299c9d <__page_cache_release+45>:   mov    (%rbx),%rax
0xffffffff81299ca0 <__page_cache_release+48>:   test   $0x200000,%eax
0xffffffff81299ca5 <__page_cache_release+53>:   jne    0xffffffff81299de4 <__page_cache_release+372>
0xffffffff81299cab <__page_cache_release+59>:   mov    -0x30(%rbp),%rax
0xffffffff81299caf <__page_cache_release+63>:   sub    %gs:0x28,%rax
0xffffffff81299cb8 <__page_cache_release+72>:   jne    0xffffffff81299e70 <__page_cache_release+512>
0xffffffff81299cbe <__page_cache_release+78>:   add    $0x20,%rsp
0xffffffff81299cc2 <__page_cache_release+82>:   pop    %rbx
0xffffffff81299cc3 <__page_cache_release+83>:   pop    %r12
0xffffffff81299cc5 <__page_cache_release+85>:   pop    %r13
0xffffffff81299cc7 <__page_cache_release+87>:   pop    %r14
0xffffffff81299cc9 <__page_cache_release+89>:   pop    %r15
0xffffffff81299ccb <__page_cache_release+91>:   pop    %rbp
0xffffffff81299ccc <__page_cache_release+92>:   ret    
0xffffffff81299ccd <__page_cache_release+93>:   int3   
0xffffffff81299cce <__page_cache_release+94>:   int3   
0xffffffff81299ccf <__page_cache_release+95>:   int3   
0xffffffff81299cd0 <__page_cache_release+96>:   int3   
0xffffffff81299cd1 <__page_cache_release+97>:   lea    -0x38(%rbp),%rsi
0xffffffff81299cd5 <__page_cache_release+101>:  mov    %rbx,%rdi
0xffffffff81299cd8 <__page_cache_release+104>:  movq   $0x0,-0x38(%rbp)
0xffffffff81299ce0 <__page_cache_release+112>:  call   0xffffffff8131a510 <folio_lruvec_lock_irqsave>
0xffffffff81299ce5 <__page_cache_release+117>:  mov    %rax,%r12
0xffffffff81299ce8 <__page_cache_release+120>:  mov    (%rbx),%rax
0xffffffff81299ceb <__page_cache_release+123>:  test   $0x100000,%eax
0xffffffff81299cf0 <__page_cache_release+128>:  jne    0xffffffff81299e48 <__page_cache_release+472>
0xffffffff81299cf6 <__page_cache_release+134>:  mov    (%rbx),%rax
0xffffffff81299cf9 <__page_cache_release+137>:  mov    (%rbx),%rdx
0xffffffff81299cfc <__page_cache_release+140>:  shr    $0x13,%rax
0xffffffff81299d00 <__page_cache_release+144>:  shr    $0x8,%rdx
0xffffffff81299d04 <__page_cache_release+148>:  and    $0x1,%eax
0xffffffff81299d07 <__page_cache_release+151>:  and    $0x1,%edx
0xffffffff81299d0a <__page_cache_release+154>:  xor    $0x1,%eax
0xffffffff81299d0d <__page_cache_release+157>:  movzbl %al,%eax
0xffffffff81299d10 <__page_cache_release+160>:  lea    (%rdx,%rax,2),%r15d
0xffffffff81299d14 <__page_cache_release+164>:  mov    0x10(%rbx),%rax
0xffffffff81299d18 <__page_cache_release+168>:  mov    0x8(%rbx),%rdx
0xffffffff81299d1c <__page_cache_release+172>:  mov    %rax,0x8(%rdx) # <== crashed here
0xffffffff81299d20 <__page_cache_release+176>:  mov    %rdx,(%rax)
0xffffffff81299d23 <__page_cache_release+179>:  movabs $0xdead000000000100,%rax
0xffffffff81299d2d <__page_cache_release+189>:  mov    %rax,0x8(%rbx)
0xffffffff81299d31 <__page_cache_release+193>:  add    $0x22,%rax
0xffffffff81299d35 <__page_cache_release+197>:  mov    %rax,0x10(%rbx)
0xffffffff81299d39 <__page_cache_release+201>:  lea    0x1(%r15),%eax
0xffffffff81299d3d <__page_cache_release+205>:  mov    %eax,-0x40(%rbp)
0xffffffff81299d40 <__page_cache_release+208>:  mov    (%rbx),%r13
0xffffffff81299d43 <__page_cache_release+211>:  mov    (%rbx),%rax
0xffffffff81299d46 <__page_cache_release+214>:  mov    0x88(%r12),%r14
0xffffffff81299d4e <__page_cache_release+222>:  shr    $0x3e,%r13
0xffffffff81299d52 <__page_cache_release+226>:  test   $0x40,%al
0xffffffff81299d54 <__page_cache_release+228>:  je     0xffffffff81299e37 <__page_cache_release+455>
0xffffffff81299d5a <__page_cache_release+234>:  mov    0x64(%rbx),%eax
0xffffffff81299d5d <__page_cache_release+237>:  neg    %rax
0xffffffff81299d60 <__page_cache_release+240>:  movslq %eax,%rdx
0xffffffff81299d63 <__page_cache_release+243>:  mov    %eax,%ecx
0xffffffff81299d65 <__page_cache_release+245>:  cmp    %rdx,%rax
0xffffffff81299d68 <__page_cache_release+248>:  jne    0xffffffff81299e5a <__page_cache_release+490>
0xffffffff81299d6e <__page_cache_release+254>:  mov    %ecx,%edx
...
```