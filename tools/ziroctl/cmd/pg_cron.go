package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A five-field cron schedule (minute hour day-of-month month day-of-week, in UTC), for the Postgres
// backup schedule. Fields take *, numbers, ranges (1-5), lists (1,15) and steps (*/15, 0-30/10). As in
// cron, when both day fields are restricted a day matches if either does.

type pgCron struct {
	min, hour, dom, mon, dow [64]bool
	domAny, dowAny           bool
	spec                     string
}

func pgCronField(f string, lo, hi int, set *[64]bool) (any bool, err error) {
	for _, part := range strings.Split(f, ",") {
		step := 1
		if base, s, ok := strings.Cut(part, "/"); ok {
			if step, err = strconv.Atoi(s); err != nil || step < 1 {
				return false, fmt.Errorf("bad step in %q", f)
			}
			part = base
		}
		a, b := lo, hi
		switch {
		case part == "*":
			any = any || step == 1
		case strings.Contains(part, "-"):
			x, y, _ := strings.Cut(part, "-")
			if a, err = strconv.Atoi(x); err != nil {
				return false, fmt.Errorf("bad range in %q", f)
			}
			if b, err = strconv.Atoi(y); err != nil {
				return false, fmt.Errorf("bad range in %q", f)
			}
		default:
			if a, err = strconv.Atoi(part); err != nil {
				return false, fmt.Errorf("bad value in %q", f)
			}
			b = a
		}
		if a < lo || b > hi || a > b {
			return false, fmt.Errorf("%q is out of range %d-%d", f, lo, hi)
		}
		for v := a; v <= b; v += step {
			set[v] = true
		}
	}
	return any, nil
}

func pgParseCron(spec string) (*pgCron, error) {
	f := strings.Fields(spec)
	if len(f) != 5 {
		return nil, fmt.Errorf("a schedule has five fields (minute hour day month weekday): %q", spec)
	}
	c := &pgCron{spec: spec}
	var err error
	if _, err = pgCronField(f[0], 0, 59, &c.min); err == nil {
		if _, err = pgCronField(f[1], 0, 23, &c.hour); err == nil {
			if c.domAny, err = pgCronField(f[2], 1, 31, &c.dom); err == nil {
				if _, err = pgCronField(f[3], 1, 12, &c.mon); err == nil {
					c.dowAny, err = pgCronField(f[4], 0, 7, &c.dow)
				}
			}
		}
	}
	if err != nil {
		return nil, err
	}
	c.dow[0] = c.dow[0] || c.dow[7] // 7 is Sunday too
	return c, nil
}

func (c *pgCron) matches(t time.Time) bool {
	if !c.min[t.Minute()] || !c.hour[t.Hour()] || !c.mon[int(t.Month())] {
		return false
	}
	dom, dow := c.dom[t.Day()], c.dow[int(t.Weekday())]
	switch {
	case c.domAny && c.dowAny:
		return true
	case c.domAny:
		return dow
	case c.dowAny:
		return dom
	}
	return dom || dow
}

// prev is the last time at or before t the schedule fires (zero if none in the last 400 days).
func (c *pgCron) prev(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute)
	for i := 0; i < 400*24*60; i++ {
		if c.matches(t) {
			return t
		}
		if !c.hour[t.Hour()] || !c.mon[int(t.Month())] { // skip the rest of the hour
			t = t.Truncate(time.Hour).Add(-time.Minute)
			continue
		}
		t = t.Add(-time.Minute)
	}
	return time.Time{}
}

// gap is the longest time between two firings within the next two weeks (for "a backup is late").
func (c *pgCron) gap(from time.Time) time.Duration {
	var longest time.Duration
	last := c.prev(from)
	for t := last.Add(time.Minute); t.Before(from.Add(15 * 24 * time.Hour)); t = t.Add(time.Minute) {
		if c.matches(t) {
			longest = max(longest, t.Sub(last))
			last = t
		}
	}
	return longest
}
