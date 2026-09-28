package cmd

import (
	"bufio"
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

func readCronJobs() ([]CronJob, error) {
	var jobs []CronJob
	f, err := os.Open(crontabFile)
	if err != nil {
		return jobs, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	currentComment := ""
	id := 1

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			currentComment = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 6 {
			sched := strings.Join(fields[:5], " ")
			cmdStr := strings.Join(fields[5:], " ")
			jobs = append(jobs, CronJob{
				ID:       id,
				Schedule: sched,
				Command:  cmdStr,
				Comment:  currentComment,
			})
			id++
			currentComment = ""
		}
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

func removeCronJob(id int) error {
	jobs, err := readCronJobs()
	if err != nil {
		return err
	}

	var newLines []string
	found := false
	for _, j := range jobs {
		if j.ID == id {
			found = true
			continue
		}
		if j.Comment != "" {
			newLines = append(newLines, "# "+j.Comment)
		}
		newLines = append(newLines, fmt.Sprintf("%s %s", j.Schedule, j.Command))
	}

	if !found {
		return fmt.Errorf("job ID %d not found", id)
	}

	content := strings.Join(newLines, "\n")
	if len(newLines) > 0 {
		content += "\n"
	}
	return os.WriteFile(crontabFile, []byte(content), 0600)
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
