package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// A host reboot used to end its Postgres members the hard way: init sends every process SIGTERM, which Postgres
// reads as "smart shutdown" (wait for every client to leave), and SIGKILL three seconds later. Every member
// then replays WAL when the host comes back, a primary's replicas included, and none of them answers until it
// is done. `pg stop-local` asks each member on this node for a fast shutdown first (checkpoint, send the WAL
// to the standbys, exit), and init and `ziroctl upgrade --reboot` run it before they go on.

var pgStopLocalTimeout time.Duration

var pgStopLocalCmd = &cobra.Command{
	Use:   "stop-local",
	Short: "Shut this node's Postgres members down cleanly",
	Long: `Asks every Postgres member container on this node for a fast shutdown and waits for it, so a reboot does not
leave them to replay WAL for minutes afterwards. The containers' restart policy is untouched: the runtime starts
them again at boot as before. The command never fails the reboot: members still running after the timeout are
left to init, which ends them as it always did. ziroctl upgrade --reboot and the init shutdown run it.`,
	Example: "  ziroctl pg stop-local --timeout 2m",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("PATH") == "" { // init starts it with the environment the kernel gave it
			_ = os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
		}
		ctx, cancel := context.WithTimeout(context.Background(), pgStopLocalTimeout+30*time.Second)
		defer cancel()
		for _, l := range pgStopLocal(ctx, pgNerdctl, pgSignalFastShutdown, pgPIDAlive, pgStopLocalTimeout, time.Second) {
			fmt.Println(l)
		}
		return nil
	},
}

func init() {
	pgStopLocalCmd.Flags().DurationVar(&pgStopLocalTimeout, "timeout", 2*time.Minute, "How long the members get to shut down")
	pgCmd.AddCommand(pgStopLocalCmd)
}

// pgStopLocalBeforeReboot is `pg stop-local` for ziroctl upgrade --reboot: it says what it did, and nothing
// when there is no Postgres member on this node.
func pgStopLocalBeforeReboot() {
	if os.Getenv("PATH") == "" {
		_ = os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute+30*time.Second)
	defer cancel()
	for _, l := range pgStopLocal(ctx, pgNerdctl, pgSignalFastShutdown, pgPIDAlive, 2*time.Minute, time.Second) {
		if l != pgNoMembersHere {
			fmt.Println("  " + l)
		}
	}
}

const pgNoMembersHere = "no Postgres members are running here"

// pgMemberContainer: the container of a cluster member (zc-pgc-<cluster>-<group>-<member>-<index>-<hash>), not
// of the pooler (zc-pgc-<cluster>-pool-<index>-<hash>) or anything else.
func pgMemberContainer(name string) bool {
	parts := strings.Split(strings.TrimPrefix(name, "zc-"), "-")
	return strings.HasPrefix(name, "zc-"+pgAppPrefix) && len(parts) == 6 && parts[0]+"-" == pgAppPrefix && pgGroupRe.MatchString(parts[2])
}

// pgSignalFastShutdown sends SIGINT to the postmaster, which is the container's first process (the entry
// script ends in exec): a fast shutdown. It is sent from the host, not with `nerdctl stop`, because a stop
// marks the container stopped, and the runtime would then not start it again at boot.
func pgSignalFastShutdown(pid int) error { return syscall.Kill(pid, syscall.SIGINT) }

// pgPIDAlive: the process exists and is not a zombie waiting to be reaped.
func pgPIDAlive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	s := string(b)
	if i := strings.LastIndex(s, ")"); i >= 0 && i+2 < len(s) {
		return s[i+2] != 'Z' && s[i+2] != 'X'
	}
	return true
}

// pgStopLocal asks the members on this node for a fast shutdown and waits until they have exited or the time
// is out. It returns what it did, one line each.
func pgStopLocal(ctx context.Context, run pgRunner, signal func(pid int) error, alive func(pid int) bool, timeout, poll time.Duration) []string {
	out, err := run(ctx, "ps", "--format", "{{.Names}}")
	if err != nil {
		return []string{"no Postgres members stopped: " + condenseRuntimeError(lastOutputLine(out))}
	}
	var lines []string
	waiting := map[string]int{}
	var order []string
	for _, name := range strings.Fields(out) {
		if !pgMemberContainer(name) {
			continue
		}
		pidOut, err := run(ctx, "inspect", "-f", "{{.State.Pid}}", name)
		pid, perr := strconv.Atoi(strings.TrimSpace(lastOutputLine(pidOut)))
		if err != nil || perr != nil || pid <= 1 {
			lines = append(lines, fmt.Sprintf("%s: not running", name))
			continue
		}
		if err := signal(pid); err != nil {
			lines = append(lines, fmt.Sprintf("%s: could not be signalled: %v", name, err))
			continue
		}
		waiting[name] = pid
		order = append(order, name)
	}
	if len(order) == 0 {
		return append(lines, pgNoMembersHere)
	}
	start := time.Now()
	for len(waiting) > 0 && time.Since(start) < timeout && ctx.Err() == nil {
		for _, name := range order {
			if pid, ok := waiting[name]; ok && !alive(pid) {
				delete(waiting, name)
				lines = append(lines, fmt.Sprintf("%s: shut down cleanly after %s", name, time.Since(start).Round(time.Second)))
			}
		}
		if len(waiting) > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(poll):
			}
		}
	}
	for _, name := range order {
		if _, ok := waiting[name]; ok {
			lines = append(lines, fmt.Sprintf("%s: still running after %s: left to init", name, timeout))
		}
	}
	return lines
}
