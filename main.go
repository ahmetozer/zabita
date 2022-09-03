package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"plugin"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

type ZabitaFunc interface {
	CheckFW(*water.Interface, ethernet.Frame)
}

var (
	rulePath        string
	listenStatus    chan int
	packet          chan ethernet.Frame
	packetErr       chan error
	zabitaIf        *water.Interface
	zabitaNetlinkIf netlink.Link
	zf              ZabitaFunc
)

func main() {
	log.Println("Zabita is starting")
	listenStatus = make(chan int)
	packet = make(chan ethernet.Frame)
	packetErr = make(chan error)
	defer func() {
		if err := recover(); err != nil {
			log.Println("panic occurred:", err)
			log.Println("restarting process in 3 second")
			time.Sleep(time.Second * 3)
			restartMainProcess()
		}
	}()

	config := water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: "zabita"},
	}

	var err error
	// Create `zabita` network interface
	zabitaIf, err = water.New(config)
	if err != nil {
		log.Fatalf("error while creating new interface %e", err)
	}

	// Setup network interface with netlink lib.
	zabitaNetlinkIf, err = netlink.LinkByName(config.Name)
	if err != nil {
		log.Fatalf("error while getting interface: %e", err)
	}
	addr4, _ := netlink.ParseAddr("169.254.20.254/31")
	addr6, _ := netlink.ParseAddr("fd:900d:cafe:7a61:6269:7461::/127")
	netlink.AddrAdd(zabitaNetlinkIf, addr4)
	netlink.AddrAdd(zabitaNetlinkIf, addr6)
	netlink.LinkSetUp(zabitaNetlinkIf)

	// disable rp_filter for firewall interface to prevent packet drop.
	err = os.WriteFile("/proc/sys/net/ipv4/conf/"+config.Name+"/rp_filter", []byte{48}, 0644)
	if err != nil {
		log.Fatalf("error while setting rp filter: %e", err)
	}

	rulePath = os.Getenv("rule_path")
	if rulePath == "" {
		rulePath = "/lib"
	}
	loadModule()

	go WatchModules()

	// Read packages from interface.
	go func() {
		var frame ethernet.Frame
		for {
			frame.Resize(1500)
			n, err := zabitaIf.Read([]byte(frame))
			if err == nil {
				frame = frame[:n]
				packet <- frame
			} else {
				packetErr <- err
			}
		}
	}()

	// Start packet processing if system is ready.
	go func() {
	packetLoop:
		for {
			select {
			case <-listenStatus:
				log.Printf("packet listening will stopped\n")
				break packetLoop
			case p := <-packet:
				go func() {
					defer func() {
						if err := recover(); err != nil {
							log.Println("firewall rule panic:", err)
						}
					}()
					// packet processing function
					zf.CheckFW(zabitaIf, p)
				}()
			case err := <-packetErr:
				log.Printf("packet read error: %e", err)
			}

		}
		log.Printf("packet listening stopped\n")
	}()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	s := <-c
	log.Printf("os signal: %s", s)
	os.Exit(0)

}

// To detect changes on the rule file `zabita_rule.so` to start
// reload process of
func WatchModules() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	err = watcher.Add(rulePath)
	if err != nil {
		log.Fatal(err)
	}
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if filepath.Base(strings.Split(event.Name, ":")[0]) == "zabita_rule.so" {
				log.Printf("rule watcher: change detected")
				listenStatus <- 0
				restartMainProcess()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Println("rule watcher:", err)
		}
	}
}

// Load external functions that is handles packet filtering.
func loadModule() {
	plug, err := plugin.Open(rulePath + "/zabita_rule.so")
	if err != nil {
		log.Fatalf("firewall rule load error: %s\n", err)
	}

	z, err := plug.Lookup("ZabitaFunc")
	if err != nil {
		log.Fatalf("err %e\n", err)
	}
	var ok bool
	zf, ok = z.(ZabitaFunc)
	if !ok {
		log.Fatalf("unexpected type from module symbol")
	}

	M, err := plug.Lookup("Main")
	if err != nil {
		log.Fatalf("err %e\n", err)
	}

	// Custom Main process of the rule
	M.(func())()

}

// Re execute it self with replace previous process.
func restartMainProcess() {
	zabitaIf.Close()

	log.Printf("switching to the new process")
	binPath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	if err := syscall.Exec(binPath, os.Args, os.Environ()); err != nil {
		log.Fatalf("exec err: %s\n", err)
	}
}
