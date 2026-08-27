# XNU Hardened Exception Flavor Confusion
Educational write-up of an XNU hardened Mach exception flavor-confusion kernel panic fixed in macOS 26.5.
> A historical analysis of a user-triggerable kernel panic in the hardened Mach exception state-restore path.

**Researcher:** Ahmed Aldeab  
**X/Twitter:** [@0xfa7b](https://x.com/0xfa7b)  
**Impact:** Local denial of service — kernel panic and forced reboot  
**Affected component:** XNU Mach exceptions on arm64/arm64e  
**Status:** Reported to Apple; fixed in macOS 26.5

## Overview

The bug was a trust-boundary and state-consistency failure in XNU's hardened exception handling path. A task could register a user-space exception handler, receive an exception-state message, and return a different thread-state `flavor` than the one originally requested by the kernel.

The kernel reused this IPC-modified value when restoring the thread state, while continuing to use the original state buffer and count. In the arm64 conversion routine, that inconsistent pair could leave the saved 64-bit state pointer as `NULL`. The hardened `TSSF_ONLY_PC` path then copied from the null pointer, producing a kernel data abort at address zero.

The confirmed security impact was a deterministic local kernel panic. This issue was not demonstrated as code execution, privilege escalation, or an information disclosure.

## Affected code path

The relevant flow crossed several layers:

```text
userspace exception handler
          │
          ▼
mach_msg() / exception_raise_state()
          │
          ▼
osfmk/kern/exception.c: exception_deliver()
          │  flavor is returned through an inout IPC argument
          ▼
osfmk/kern/thread_act.c: thread_setstatus_from_user()
          │
          ▼
osfmk/arm64/status.c: machine_thread_state_convert_from_user()
          │
          ▼
memcpy(..., old_ts64, ...), where old_ts64 may be NULL
```

The hardened registration and adoption logic involved `osfmk/kern/ipc_tt.c`, while the IPC contract was described by `osfmk/mach/exc.defs`.

## Root cause

### 1. The original flavor and saved state

In `exception_deliver()`, the kernel selected a registered exception flavor and used it to obtain the old thread state:

```c
flavor = excp->flavor;
old_state_cnt = _MachineStateCount[flavor];

kr = thread_getstatus_to_user(thread, flavor,
    (thread_state_t)old_state, &old_state_cnt, get_flags);
```

For a hardened exception, the kernel also enabled the restricted restore mode:

```c
if (excp->hardened) {
    set_flags |= TSSF_ONLY_PC;
}
```

### 2. The flavor crossed an IPC trust boundary

The same `flavor` variable was passed to the exception server through an `inout` argument:

```c
kr = exception_raise_state(exc_port, exception,
    small_code, codeCnt,
    &flavor,
    old_state, old_state_cnt,
    new_state, &new_state_cnt);
```

The exception server was therefore able to return a flavor different from the flavor used to create `old_state` and `old_state_cnt`.

### 3. The returned flavor was reused without cross-validation

After the IPC call, the kernel used the returned value together with the original saved-state metadata:

```c
kr = thread_setstatus_from_user(thread, flavor,
    (thread_state_t)new_state, new_state_cnt,
    (thread_state_t)old_state, old_state_cnt,
    set_flags);
```

The missing invariant was:

```text
returned flavor and returned state count
must remain compatible with the flavor and count of old_state
```

### 4. NULL dereference in the arm64 conversion routine

In `machine_thread_state_convert_from_user()`, the old 64-bit state pointer was initialized to `NULL` and populated only when the old count matched the currently selected flavor representation:

```c
arm_thread_state64_t *old_ts64 = NULL;

case ARM_THREAD_STATE: {
    ...
    if (old_unified_state &&
        old_count >= ARM_UNIFIED_THREAD_STATE_COUNT) {
        old_ts64 = thread_state64(old_unified_state);
    }
    break;
}
```

The restricted restore path then assumed that pointer was valid:

```c
if (only_set_pc) {
    uint64_t new_pc = ts64->pc;
    uint64_t new_flags = ts64->flags;

    memcpy(ts64, old_ts64, sizeof(arm_thread_state64_t));
    ts64->pc = new_pc;
    ts64->flags = new_flags;
}
```

If the returned flavor selected the unified `ARM_THREAD_STATE` representation while `old_state_cnt` still described `ARM_THREAD_STATE64`, `old_ts64` remained `NULL`. Because `TSSF_ONLY_PC` was active for the hardened path, the `memcpy()` dereferenced address zero in kernel context.

## Trigger sequence

At a high level, the crash required the following sequence:

1. A normal user process registers a hardened exception handler for one of its own threads.
2. The handler is configured for `ARM_THREAD_STATE64`.
3. The thread generates a catchable exception, such as an undefined instruction.
4. The exception server receives `exception_raise_state`.
5. The server returns a structurally inconsistent response: a different flavor together with a state/count pair accepted by the new-state parser.
6. `exception_deliver()` passes the modified flavor and the original old-state metadata into the thread-state restore path.
7. The arm64 conversion routine reaches the `TSSF_ONLY_PC` copy and faults through a null `old_ts64` pointer.

This was a crash-only primitive. Memory grooming was not required for the demonstrated impact; the result was a kernel panic and reboot.

## Observed result

The affected test system produced a panic consistent with a kernel data abort at virtual address zero. The report covered macOS 15 Sequoia build `24E248` / Darwin `24.4.0`, using XNU `11417.101.15`.

Representative panic indicators included:

```text
Debugger message: panic
Kernel data abort
far: 0x0000000000000000
```

## Security impact

The vulnerability allowed an unprivileged local process to crash the operating system from user space. The practical impact was:

- kernel panic;
- forced system reboot;
- local denial of service.

The research did not establish arbitrary kernel read/write, information disclosure, or privilege escalation. Those impacts should not be inferred from the null dereference alone.

## SO..

The IPC output parameters must be treated as untrusted, even when the server is an exception handler belonging to the same process. Any value returned across the boundary must be validated against all state captured before the call.

In particular, state conversion APIs should either:

- reject incompatible `(flavor, count, old_state)` combinations before entering architecture-specific code; or
- validate every derived pointer before use, including restricted/hardened paths.

Security hardening can also create a narrower path that exposes assumptions not exercised by ordinary state restoration. The `TSSF_ONLY_PC` mode was intended to constrain register modification, but it made the inconsistent old-state relationship fatal.

## Disclosure

The issue was reported to Apple and was fixed in **macOS 26.5**. This write-up is intended for educational analysis of the state-machine and trust-boundary failure; readers should use patched operating systems and should not reproduce the crash on production systems.

## Credits

Discovered and reported by **Ahmed Aldeab** — [@0xfa7b](https://x.com/0xfa7b).

---

*Educational write-up. No exploit for code execution or privilege escalation is claimed.*
