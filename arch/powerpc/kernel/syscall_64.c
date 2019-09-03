#include <linux/err.h>
#include <asm/book3s/64/kup-radix.h>
#include <asm/cputime.h>
#include <asm/hw_irq.h>
#include <asm/paca.h>
#include <asm/ptrace.h>
#include <asm/reg.h>
#include <asm/signal.h>
#include <asm/switch_to.h>
#include <asm/syscall.h>
#include <asm/time.h>

extern void __noreturn tabort_syscall(void);

typedef long (*syscall_fn)(long, long, long, long, long, long);

long system_call_exception(long r3, long r4, long r5, long r6, long r7, long r8, unsigned long r0, struct pt_regs *regs)
{
	unsigned long ti_flags;
	syscall_fn f;

	BUG_ON(!(regs->msr & MSR_PR));

	if (IS_ENABLED(CONFIG_PPC_TRANSACTIONAL_MEM) &&
			unlikely(regs->msr & MSR_TS_T))
		tabort_syscall();

	account_cpu_user_entry();

#ifdef CONFIG_PPC_SPLPAR
	if (IS_ENABLED(CONFIG_VIRT_CPU_ACCOUNTING_NATIVE) &&
			firmware_has_feature(FW_FEATURE_SPLPAR)) {
		struct lppaca *lp = get_lppaca();

		if (unlikely(local_paca->dtl_ridx != lp->dtl_idx))
			accumulate_stolen_time();
	}
#endif

	kuap_check_amr();

	/*
	 * A syscall should always be called with interrupts enabled
	 * so we just unconditionally hard-enable here. When some kind
	 * of irq tracing is used, we additionally check that condition
	 * is correct
	 */
	if (IS_ENABLED(CONFIG_PPC_IRQ_SOFT_MASK_DEBUG)) {
		WARN_ON(irq_soft_mask_return() != IRQS_ENABLED);
		WARN_ON(local_paca->irq_happened);
	}
	/*
	 * This is not required for the syscall exit path, but makes the
	 * stack frame look nicer. If this was initialised in the first stack
	 * frame, or if the unwinder was taught the first stack frame always
	 * returns to user with IRQS_ENABLED, this store could be avoided!
	 */
	regs->softe = IRQS_ENABLED;

	__hard_irq_enable();

	ti_flags = current_thread_info()->flags;
	if (unlikely(ti_flags & _TIF_SYSCALL_DOTRACE)) {
		/*
		 * We use the return value of do_syscall_trace_enter() as the
		 * syscall number. If the syscall was rejected for any reason
		 * do_syscall_trace_enter() returns an invalid syscall number
		 * and the test below against NR_syscalls will fail.
		 */
		r0 = do_syscall_trace_enter(regs);
	}

	if (unlikely(r0 >= NR_syscalls))
		return -ENOSYS;

	/* May be faster to do array_index_nospec? */
	barrier_nospec();

	if (unlikely(ti_flags & _TIF_32BIT)) {
		f = (void *)compat_sys_call_table[r0];

		r3 &= 0x00000000ffffffffULL;
		r4 &= 0x00000000ffffffffULL;
		r5 &= 0x00000000ffffffffULL;
		r6 &= 0x00000000ffffffffULL;
		r7 &= 0x00000000ffffffffULL;
		r8 &= 0x00000000ffffffffULL;

	} else {
		f = (void *)sys_call_table[r0];
	}

	return f(r3, r4, r5, r6, r7, r8);
}

unsigned long syscall_exit_prepare(unsigned long r3, struct pt_regs *regs)
{
	unsigned long *ti_flagsp = &current_thread_info()->flags;
	unsigned long ti_flags;
	unsigned long ret = 0;

	regs->result = r3;

	/* Check whether the syscall is issued inside a restartable sequence */
	rseq_syscall(regs);

	ti_flags = *ti_flagsp;

	if (unlikely(r3 >= (unsigned long)-MAX_ERRNO)) {
		if (likely(!(ti_flags & (_TIF_NOERROR | _TIF_RESTOREALL)))) {
			r3 = -r3;
			regs->ccr |= 0x10000000; /* Set SO bit in CR */
		}
	}

	if (unlikely(ti_flags & _TIF_PERSYSCALL_MASK)) {
		if (ti_flags & _TIF_RESTOREALL)
			ret = _TIF_RESTOREALL;
		else
			regs->gpr[3] = r3;
		clear_bits(_TIF_PERSYSCALL_MASK, ti_flagsp);
	} else {
		regs->gpr[3] = r3;
	}

	if (unlikely(ti_flags & _TIF_SYSCALL_DOTRACE))
		do_syscall_trace_leave(regs);

again:
	local_irq_disable();
	ti_flags = READ_ONCE(*ti_flagsp);
	while (unlikely(ti_flags & _TIF_USER_WORK_MASK)) {
		local_irq_enable();
		if (ti_flags & _TIF_NEED_RESCHED) {
			schedule();
		} else {
			/*
			 * SIGPENDING must restore signal handler function
			 * argument GPRs, and some non-volatiles (e.g., r1).
			 * Restore all for now. This could be made lighter.
			 */
			if (ti_flags & _TIF_SIGPENDING)
				ret |= _TIF_RESTOREALL;
			do_notify_resume(regs, ti_flags);
		}
		local_irq_disable();
		ti_flags = READ_ONCE(*ti_flagsp);
	}

	if (IS_ENABLED(CONFIG_PPC_FPU)) {
		unsigned long mathflags = MSR_FP;

		if (IS_ENABLED(CONFIG_ALTIVEC))
			mathflags |= MSR_VEC;

		if ((regs->msr & mathflags) != mathflags)
			restore_math(regs);
	}

	/* This pattern matches prep_irq_for_idle */
	__mtmsrd(0, 1);	/* Disable MSR_EE and MSR_RI */
	if (unlikely(lazy_irq_pending())) {
		__mtmsrd(MSR_RI, 1);
		local_paca->irq_happened |= PACA_IRQ_HARD_DIS;
		local_irq_enable();
		/* Took an interrupt which may have more exit work to do. */
		goto again;
	}
	trace_hardirqs_on();
	local_paca->irq_happened &= ~PACA_IRQ_HARD_DIS;
	irq_soft_mask_set(IRQS_ENABLED);

#ifdef CONFIG_PPC_TRANSACTIONAL_MEM
	local_paca->tm_scratch = regs->msr;
#endif

	kuap_check_amr();

	account_cpu_user_exit();

	return ret;
}

