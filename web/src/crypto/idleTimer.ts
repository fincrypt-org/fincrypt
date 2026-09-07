/**
 * Idle auto-lock timer (C1.6). DEFAULT OFF — P2's UI decides whether to
 * start it. Pure timer mechanics; the lock action is injected.
 */

export interface IdleTimerHandle {
  stop(): void
}

/**
 * startIdleTimer: calls onIdle after `minutes` without reset.
 * Returns a handle with stop() and an activity-reset function.
 */
export function startIdleTimer(
  minutes: number,
  onIdle: () => void,
): IdleTimerHandle & { reset(): void } {
  let timer: ReturnType<typeof setTimeout> | null = null
  const ms = minutes * 60_000
  const arm = (): void => {
    timer = setTimeout(onIdle, ms)
  }
  arm()
  return {
    stop: () => {
      if (timer) clearTimeout(timer)
      timer = null
    },
    reset: () => {
      if (timer) clearTimeout(timer)
      arm()
    },
  }
}