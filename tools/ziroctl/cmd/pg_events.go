package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/spf13/cobra"
)

// The event history of a cluster: role changes, repairs, rolling changes, backups and alerts, kept in
// cluster state (so it survives a master change) as a ring of the last pgEventsKept per group.
// `pg status` shows the latest few; `pg events` all of them, and follows new ones.

const (
	pgEventsKept   = 200 // per group
	pgEventsStatus = 10  // shown by pg status
)

// pgEventView is one event for pg events and the API.
type pgEventView struct {
	At       time.Time `json:"at"`
	Group    string    `json:"group"`
	Severity string    `json:"severity,omitempty"` // the alert it raised, if any
	Message  string    `json:"message"`
}

// pgEventsOf lists a cluster's events after since (zero: all), oldest first, from one group or all.
func pgEventsOf(c *PGCluster, group string, since time.Time) []pgEventView {
	out := []pgEventView{}
	for _, g := range c.Groups {
		if group != "" && g.Name != group {
			continue
		}
		for _, e := range g.Events {
			if e.At.After(since) {
				out = append(out, pgEventView{At: e.At.UTC(), Group: g.Name, Severity: e.Alert, Message: e.Msg})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

var pgEventsFlags struct {
	group, since string
	follow       bool
}

var pgEventsCmd = &cobra.Command{
	Use:   "events <name>",
	Short: "Show a cluster's event history",
	Long: `Lists what happened to the cluster, oldest first: promotions, switchovers, repairs, rolling changes, backups and
alerts (marked with their severity). The last 200 events of each group are kept in cluster state. --since limits
the list to a recent period, --follow keeps printing new events.`,
	Example: "  ziroctl pg events shop\n  ziroctl pg events shop --since 24h\n  ziroctl pg events shop --follow",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := requireMaster(); err != nil {
			return err
		}
		var since time.Time
		if s := pgEventsFlags.since; s != "" {
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				return fmt.Errorf("--since: a duration such as 24h")
			}
			since = time.Now().Add(-d)
		}
		read := func() ([]pgEventView, error) {
			st, err := readState()
			if err != nil {
				return nil, err
			}
			c, err := pgCluster(st, args[0])
			if err != nil {
				return nil, err
			}
			if pgEventsFlags.group != "" && c.group(pgEventsFlags.group) == nil {
				return nil, fmt.Errorf("%s has no group %s", args[0], pgEventsFlags.group)
			}
			return pgEventsOf(c, pgEventsFlags.group, since), nil
		}
		events, err := read()
		if err != nil {
			return err
		}
		if !pgEventsFlags.follow {
			return printResult(events, func() {
				if len(events) == 0 {
					fmt.Println("no events")
				}
				for _, e := range events {
					fmt.Println(pgEventLine(e))
				}
			})
		}
		for {
			for _, e := range events {
				if jsonOutput {
					b, _ := json.Marshal(e) // one event per line
					fmt.Println(string(b))
				} else {
					fmt.Println(pgEventLine(e))
				}
				since = e.At
			}
			time.Sleep(2 * time.Second)
			if events, err = read(); err != nil {
				return err
			}
		}
	},
}

func pgEventLine(e pgEventView) string {
	sev := ""
	if e.Severity != "" {
		sev = "[" + e.Severity + "] "
	}
	return fmt.Sprintf("%s  %-5s %s%s", e.At.Format("2006-01-02 15:04:05"), e.Group, sev, e.Message)
}

// registerPGEventRoutes: GET /api/v1/pg/{name}/events?since=RFC3339&group=g (viewer).
func registerPGEventRoutes(a *apiRouter) {
	a.get("/api/v1/pg/{name}/events", "viewer", func(w http.ResponseWriter, r *http.Request) {
		var since time.Time
		if s := r.URL.Query().Get("since"); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				apiReply(w, fmt.Errorf("since must be an RFC 3339 time"), nil)
				return
			}
			since = t
		}
		st, err := readState()
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		c, err := pgCluster(st, r.PathValue("name"))
		if err != nil {
			apiReply(w, err, nil)
			return
		}
		apiReply(w, nil, pgEventsOf(c, r.URL.Query().Get("group"), since))
	})
}

func init() {
	f := pgEventsCmd.Flags()
	f.StringVar(&pgEventsFlags.group, "group", "", "Only this group")
	f.StringVar(&pgEventsFlags.since, "since", "", "Only events this recent (24h)")
	f.BoolVar(&pgEventsFlags.follow, "follow", false, "Keep printing new events")
	pgCmd.AddCommand(pgEventsCmd)
}
