/*
Copyright 2019 Adevinta
*/

package push

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// APICheck represents the checker the push api communicates with.
// This is usefull to write unit tests because makes mocking dependencies of this component easier.
type APICheck interface {
	Abort() error
}

// API implements the rest interface every check has to expose.
type API struct {
	logger     *log.Entry
	check      APICheck
	stop       chan interface{}
	ExitSignal chan os.Signal
	wg         *sync.WaitGroup
}

// Run Starts the goroutine that listens for SIGTERM signal.
func (p *API) Run() {
	p.stop = make(chan interface{})
	p.wg.Add(1)
	// Monitor SIGTERM and call Abort if received.
	go func() {
		defer p.wg.Done()
		exit := false
		aborted := false
		for !exit {
			select {
			case <-p.ExitSignal:
				if !aborted {
					p.logger.Warn("Exit signal received canceling check")
					if err := p.check.Abort(); err != nil {
						p.logger.WithError(err).Error("Aborting check.")
					}

					aborted = true
				}
			case <-p.stop:
				exit = true
				p.logger.Debug("Stop received")
			}
		}
	}()

}

// Shutdown stops the goroutine that listens for SIGTERM signal.
func (p *API) Shutdown() error {
	p.stop <- true
	p.wg.Wait()
	return nil
}

// NewPushAPI creates a PushAPI.
func newPushAPI(logger *log.Entry, check APICheck) *API {
	a := &API{
		check:      check,
		logger:     logger,
		stop:       make(chan interface{}),
		wg:         &sync.WaitGroup{},
		ExitSignal: make(chan os.Signal, 1),
	}
	signal.Notify(a.ExitSignal, syscall.SIGINT, syscall.SIGTERM)
	logger.Debug("New push api created")
	return a
}
