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
	Short:   "Manage scheduled jobs and cron tasks in Ziro-OS",
}

var cronListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all scheduled cron jobs",
	Run: func(cmd *cobra.Command, args []string) {
		jobs, err := readCronJobs()
		if err != nil {
			fmt.Println("No active cron jobs found.")
			return
		}
		if len(jobs) == 0 {
			fmt.Println("No active cron jobs found.")
			return
		}

		fmt.Printf("%-4s %-20s %-35s %s\n", "ID", "SCHEDULE", "COMMAND", "COMMENT")
		fmt.Println(strings.Repeat("-", 80))
		for _, j := range jobs {
			fmt.Printf("%-4d %-20s %-35s %s\n", j.ID, j.Schedule, j.Command, j.Comment)
		}
	},
}

var (
	cronSchedule string
	cronCommand  string
	cronComment  string
)

var cronAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new scheduled cron job",
	Run: func(cmd *cobra.Command, args []string) {
		if cronSchedule == "" || cronCommand == "" {
			fmt.Println("Error: Both --schedule and --command are required.")
			return
		}

		jobLine := fmt.Sprintf("%s %s", cronSchedule, cronCommand)
		if cronComment != "" {
			jobLine = fmt.Sprintf("# %s\n%s", cronComment, jobLine)
		}

		if err := appendCronLine(jobLine); err != nil {
			fmt.Printf("Failed to add cron job: %v\n", err)
			return
		}

		fmt.Printf("✓ Cron job added: [%s] %s\n", cronSchedule, cronCommand)
	},
}

var cronRemoveCmd = &cobra.Command{
	Use:   "remove <id>",
	Short: "Remove a scheduled cron job by its ID",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Invalid ID: must be an integer")
			return
		}

		if err := removeCronJob(id); err != nil {
			fmt.Printf("Failed to remove cron job: %v\n", err)
			return
		}

		fmt.Printf("✓ Cron job ID %d removed successfully.\n", id)
	},
}

var cronRunCmd = &cobra.Command{
	Use:   "run <id>",
	Short: "Execute a scheduled cron job immediately",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Invalid ID: must be an integer")
			return
		}

		jobs, err := readCronJobs()
		if err != nil {
			fmt.Printf("Failed to read jobs: %v\n", err)
			return
		}

		var target *CronJob
		for _, j := range jobs {
			if j.ID == id {
				target = &j
				break
			}
		}

		if target == nil {
			fmt.Printf("Cron job with ID %d not found.\n", id)
			return
		}

		fmt.Printf("Executing job: %s ...\n", target.Command)
		cmdRun := exec.Command("/bin/sh", "-c", target.Command)
		cmdRun.Stdout = os.Stdout
		cmdRun.Stderr = os.Stderr
		if err := cmdRun.Run(); err != nil {
			fmt.Printf("Job execution failed: %v\n", err)
			return
		}
		fmt.Println("✓ Job executed successfully.")
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
