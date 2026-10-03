package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

const (
	crontabFile = "/etc/crontabs/root"
)

type CronJob struct {
	ID       int    `json:"id"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Comment  string `json:"comment"`
}

var cronCmd = &cobra.Command{
	Use:     "cron",
	Aliases: []string{"cronjob", "schedule"},
	Short:   "Manage scheduled jobs",
	Example: `  ziroctl cron add -s '0 2 * * *' -c 'ziroctl backup create' -m nightly-backup
  ziroctl cron list`,
}

var cronListCmd = &cobra.Command{
	Use:     "list",
	Short:   "List scheduled jobs",
	Example: `  ziroctl cron list`,
	RunE: func(cmd *cobra.Command, args []string) error {
		jobs, err := readCronJobs()
		if err != nil {
			fmt.Println("No active cron jobs found.")
			return nil
		}
		if len(jobs) == 0 {
			fmt.Println("No active cron jobs found.")
			return nil
		}

		fmt.Printf("%-4s %-20s %-35s %s\n", "ID", "SCHEDULE", "COMMAND", "COMMENT")
		fmt.Println(strings.Repeat("-", 80))
		for _, j := range jobs {
			fmt.Printf("%-4d %-20s %-35s %s\n", j.ID, j.Schedule, j.Command, j.Comment)
		}
		return nil
	},
}

var (
	cronSchedule string
	cronCommand  string
	cronComment  string
)

var cronAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Schedule a command",
	Example: `  ziroctl cron add -s '*/5 * * * *' -c '/usr/local/bin/healthcheck.sh'
  ziroctl cron add -s '0 2 * * *' -c 'ziroctl backup create' -m nightly-backup`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cronSchedule == "" || cronCommand == "" {
			return fmt.Errorf("both --schedule and --command are required")
		}
		// One job must stay one crontab line: a newline would inject extra root cron entries.
		if strings.ContainsAny(cronSchedule+cronCommand+cronComment, "\r\n") {
			return fmt.Errorf("--schedule, --command and --comment must not contain newlines")
		}

		jobLine := fmt.Sprintf("%s %s", cronSchedule, cronCommand)
		if cronComment != "" {
			jobLine = fmt.Sprintf("# %s\n%s", cronComment, jobLine)
		}

		if err := appendCronLine(jobLine); err != nil {
			return fmt.Errorf("add cron job: %w", err)
		}

		fmt.Printf("✓ Cron job added: [%s] %s\n", cronSchedule, cronCommand)
		return nil
	},
}

var cronRemoveCmd = &cobra.Command{
	Use:     "remove <id>",
	Short:   "Remove a scheduled job",
	Example: `  ziroctl cron remove 3`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid ID: must be an integer")
		}

		if err := removeCronJob(id); err != nil {
			return fmt.Errorf("remove cron job: %w", err)
		}

		fmt.Printf("✓ Cron job ID %d removed successfully.\n", id)
		return nil
	},
}

var cronRunCmd = &cobra.Command{
	Use:     "run <id>",
	Short:   "Run a scheduled job now",
	Example: `  ziroctl cron run 3`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid ID: must be an integer")
		}

		jobs, err := readCronJobs()
		if err != nil {
			return fmt.Errorf("read jobs: %w", err)
		}

		var target *CronJob
		for _, j := range jobs {
			if j.ID == id {
				target = &j
				break
			}
		}

		if target == nil {
			return fmt.Errorf("cron job with ID %d not found", id)
		}

		fmt.Printf("Executing job: %s ...\n", target.Command)
		cmdRun := exec.Command("/bin/sh", "-c", target.Command)
		cmdRun.Stdout = os.Stdout
		cmdRun.Stderr = os.Stderr
		if err := cmdRun.Run(); err != nil {
			return fmt.Errorf("job execution failed: %w", err)
		}
		fmt.Println("✓ Job executed successfully.")
		return nil
	},
}

// parseCronLine recognises "m h dom mon dow cmd" and "@reboot/@daily cmd" lines;
// comments, blank lines and VAR=value lines are not jobs.
func parseCronLine(line string) (sched, command string, ok bool) {
	fields := strings.Fields(line)
	switch {
	case len(fields) >= 2 && strings.HasPrefix(fields[0], "@"):
		return fields[0], strings.Join(fields[1:], " "), true
	case len(fields) >= 6 && !strings.Contains(fields[0], "="):
		return strings.Join(fields[:5], " "), strings.Join(fields[5:], " "), true
	}
	return "", "", false
}

func readCrontabLines() ([]string, error) {
	data, err := os.ReadFile(crontabFile)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n"), nil
}

func readCronJobs() ([]CronJob, error) {
	lines, err := readCrontabLines()
	if err != nil {
		return nil, err
	}
	var jobs []CronJob
	currentComment := ""
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			currentComment = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			continue
		}
		if sched, command, ok := parseCronLine(line); ok {
			jobs = append(jobs, CronJob{ID: len(jobs) + 1, Schedule: sched, Command: command, Comment: currentComment})
		}
		currentComment = ""
	}
	return jobs, nil
}

func appendCronLine(line string) error {
	_ = os.MkdirAll(filepath.Dir(crontabFile), 0755)
	f, err := os.OpenFile(crontabFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line + "\n")
	return err
}

// removeCronJob deletes one job (and its comment) and keeps every other line verbatim.
func removeCronJob(id int) error {
	lines, err := readCrontabLines()
	if err != nil {
		return err
	}
	n := 0
	for i, raw := range lines {
		if _, _, ok := parseCronLine(strings.TrimSpace(raw)); !ok {
			continue
		}
		if n++; n != id {
			continue
		}
		start := i
		if i > 0 && strings.HasPrefix(strings.TrimSpace(lines[i-1]), "#") {
			start = i - 1
		}
		kept := append(append([]string{}, lines[:start]...), lines[i+1:]...)
		content := strings.Join(kept, "\n")
		if len(kept) > 0 {
			content += "\n"
		}
		return os.WriteFile(crontabFile, []byte(content), 0600)
	}
	return fmt.Errorf("job ID %d not found", id)
}

func init() {
	cronAddCmd.Flags().StringVarP(&cronSchedule, "schedule", "s", "", "Cron expression (e.g. '*/5 * * * *')")
	cronAddCmd.Flags().StringVarP(&cronCommand, "command", "c", "", "Command to execute")
	cronAddCmd.Flags().StringVarP(&cronComment, "comment", "m", "", "Descriptive comment")

	cronCmd.AddCommand(cronListCmd)
	cronCmd.AddCommand(cronAddCmd)
	cronCmd.AddCommand(cronRemoveCmd)
	cronCmd.AddCommand(cronRunCmd)
	rootCmd.AddCommand(cronCmd)
}
