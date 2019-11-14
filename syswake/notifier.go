package syswake

// WakeSleepSignal describes Sleep/WakeUp signal state
type WakeSleepSignal uint8

// Signals
const (
	SigSleep  WakeSleepSignal = iota // Going sleep
	SigWakeUp                        // Wake up
	SigExit                          // Interrupt/Hangup signal
	SigReload                        // Pause and WakeUp signal for daemon (not implemented)
)

// WakeSleepNotifier notifies about wakeup/
type WakeSleepNotifier interface {
	GetNotificationChannel() <-chan WakeSleepSignal
	Close()
}
