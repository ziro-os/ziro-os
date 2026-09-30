package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	Version   = "1.0.15"
	BuildDate = "2026-09-30"
	GitCommit = "dev"
)

type VersionInfo struct {
	Version   string `json:"version"`
	BuildDate string `json:"build_date"`
	GitCommit string `json:"git_commit"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show Ziro-OS and ziroctl version information",
	Run: func(cmd *cobra.Command, args []string) {
		commit := GitCommit
		if commit == "dev" || commit == "" {
			if bi, ok := debug.ReadBuildInfo(); ok {
				for _, s := range bi.Settings {
					if s.Key == "vcs.revision" {
						commit = s.Value
						if len(commit) > 7 {
							commit = commit[:7]
						}
					}
					if s.Key == "vcs.time" && (BuildDate == "" || BuildDate == "2026-09-28") {
						BuildDate = s.Value
					}
				}
			}
		}

		info := VersionInfo{
			Version:   Version,
			BuildDate: BuildDate,
			GitCommit: commit,
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		}

		out := cmd.OutOrStdout()
		if jsonOutput {
			data, _ := json.MarshalIndent(info, "", "  ")
			fmt.Fprintln(out, string(data))
			return
		}

		fmt.Fprintf(out, "ziroctl version %s (%s/%s)\n", info.Version, info.OS, info.Arch)
		fmt.Fprintf(out, "Git Commit: %s\n", info.GitCommit)
		fmt.Fprintf(out, "Build Date: %s\n", info.BuildDate)
		fmt.Fprintf(out, "Go Version: %s\n", info.GoVersion)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
