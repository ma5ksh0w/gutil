//+build darwin

package syswake

import (
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	notif "github.com/prashantgupta24/mac-sleep-notifier/notifier"
)

type notifier struct {
	open      int32
	notifChan chan WakeSleepSignal
	close     chan struct{}
	wg        sync.WaitGroup
}

// NewNotifier returns new syswake notifier
func NewNotifier() WakeSleepNotifier {
	return new(notifier)
}

func (c *notifier) GetNotificationChannel() <-chan WakeSleepSignal {
	if atomic.LoadInt32(&c.open) == 0 {
		c.createNotificationChannel()
	}

	return c.notifChan
}

func (c *notifier) createNotificationChannel() {
	if atomic.AddInt32(&c.open, 1) != 1 {
		return
	}

	c.notifChan = make(chan WakeSleepSignal, 1)
	c.close = make(chan struct{})

	c.wg.Add(1)
	go c.watch()
}

func (c *notifier) watch() {
	defer c.wg.Done()
	defer close(c.notifChan)
	defer atomic.StoreInt32(&c.open, 0)

	cn := make(chan os.Signal)
	signal.Notify(cn, os.Interrupt, syscall.SIGINT, syscall.SIGHUP)
	defer close(cn)

	wakeSleepCh := notif.GetInstance().Start()
	defer notif.GetInstance().Quit()

	for {
		select {
		case <-c.close:
			return

		case _ = <-cn:
			c.notifChan <- SigExit

		case act := <-wakeSleepCh:
			if act.Type == notif.Awake {
				c.notifChan <- SigWakeUp
			} else if act.Type == notif.Sleep {
				c.notifChan <- SigSleep
			}
		}
	}
}

func (c *notifier) Close() {
	if atomic.LoadInt32(&c.open) == 0 {
		return
	}

	select {
	case <-c.close:
	default:
		close(c.close)
	}

	c.wg.Wait()
}
