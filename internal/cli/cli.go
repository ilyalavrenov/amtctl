package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/ilyalavrenov/amtctl/internal/amt"
	"github.com/ilyalavrenov/amtctl/internal/sol"
)

// dialTimeout bounds the redirection connect; an unreachable AMT host would
// otherwise hang until the OS gives up.
const dialTimeout = 15 * time.Second

const (
	flagHost   = "host"
	flagTLS    = "tls"
	flagUser   = "user"
	flagPass   = "pass"
	flagState  = "state"
	flagDevice = "device"
	flagJSON   = "json"
)

// Run executes the command tree against argv. Cancelling ctx aborts the console
// session; the WSMAN commands cannot observe it, see amt.parameters.
func Run(ctx context.Context, version string, osArgs []string) error {
	return command(version).Run(ctx, osArgs) //nolint:wrapcheck // error is already contextual
}

func command(version string) *cli.Command {
	return &cli.Command{
		Name:                  "amtctl",
		Usage:                 "out-of-band control for Intel AMT (vPro) machines",
		Version:               version,
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  flagJSON,
				Usage: "print machine-readable JSON instead of plain text",
			},
		},
		Commands: []*cli.Command{
			infoCommand(),
			devicesCommand(),
			bootCommand(),
			powerCommand(),
			solCommand(),
		},
	}
}

func connectionFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     flagHost,
			Usage:    "AMT host or IP",
			Sources:  cli.EnvVars("AMT_HOST"),
			Required: true,
		},
		&cli.BoolFlag{
			Name:  flagTLS,
			Usage: "use the TLS ports (16993 WSMAN, 16995 redirection) instead of 16992/16994",
		},
		&cli.StringFlag{
			Name:     flagUser,
			Usage:    "AMT username",
			Sources:  cli.EnvVars("AMT_USER"),
			Required: true,
		},
		&cli.StringFlag{
			Name:     flagPass,
			Usage:    "AMT password",
			Sources:  cli.EnvVars("AMT_PASS"),
			Required: true,
		},
	}
}

func stateFlag(value string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:  flagState,
		Value: value,
		Usage: "power state: " + strings.Join(amt.StateNames(), "|"),
	}
}

func client(cmd *cli.Command) *amt.Client {
	return amt.New(cmd.String(flagHost), cmd.String(flagUser), cmd.String(flagPass), cmd.Bool(flagTLS))
}

func writeJSON(cmd *cli.Command, out any) error {
	encoder := json.NewEncoder(cmd.Writer)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(out); err != nil {
		return fmt.Errorf("write json: %w", err)
	}

	return nil
}

type infoOutput struct {
	PowerState   string `json:"power_state"`
	Version      string `json:"version"`
	Provisioning string `json:"provisioning"`
	ControlMode  string `json:"control_mode"`
}

func infoCommand() *cli.Command {
	return &cli.Command{
		Name:  "info",
		Usage: "report the power state and what AMT reports about itself",
		Flags: connectionFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			info, err := client(cmd).FetchInfo()
			if err != nil {
				return err
			}

			if cmd.Bool(flagJSON) {
				return writeJSON(cmd, infoOutput{
					PowerState:   info.Power,
					Version:      info.Version,
					Provisioning: info.Provisioning,
					ControlMode:  info.ControlMode,
				})
			}

			writeInfo(cmd.Writer, info)

			return nil
		},
	}
}

func writeInfo(w io.Writer, info amt.Info) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	for _, field := range [][2]string{
		{"power", info.Power},
		{"version", info.Version},
		{"provisioning", info.Provisioning},
		{"control-mode", info.ControlMode},
	} {
		if field[1] == "" {
			continue
		}

		fmt.Fprintf(tw, "%s\t%s\n", field[0], field[1])
	}

	_ = tw.Flush()
}

func powerCommand() *cli.Command {
	return &cli.Command{
		Name:  "power",
		Usage: "change the power state",
		Flags: append(connectionFlags(), stateFlag("on")),
		Action: func(_ context.Context, cmd *cli.Command) error {
			state, err := amt.ParseState(cmd.String(flagState))
			if err != nil {
				return err
			}

			return client(cmd).ChangePower(state)
		},
	}
}

type devicesOutput struct {
	Devices []string `json:"devices"`
}

func devicesCommand() *cli.Command {
	return &cli.Command{
		Name:  "devices",
		Usage: "list the boot devices this machine reports",
		Flags: connectionFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			names, err := client(cmd).Devices()
			if err != nil {
				return err
			}

			if cmd.Bool(flagJSON) {
				return writeJSON(cmd, devicesOutput{Devices: names})
			}

			for _, name := range names {
				fmt.Fprintln(cmd.Writer, name)
			}

			return nil
		},
	}
}

func bootCommand() *cli.Command {
	return &cli.Command{
		Name:  "boot",
		Usage: "force a one-time boot from a device, then apply the power action",
		Description: "Stages the boot override and enables serial-over-LAN for the next boot, " +
			"so `amtctl sol` shows the boot it triggers.",
		Flags: append(connectionFlags(), &cli.StringFlag{
			Name:  flagDevice,
			Value: "pxe",
			Usage: "boot device: " + strings.Join(amt.DeviceNames(), "|"),
		}, stateFlag("reset")),
		Action: func(_ context.Context, cmd *cli.Command) error {
			device, err := amt.ParseDevice(cmd.String(flagDevice))
			if err != nil {
				return err
			}

			state, err := amt.ParseState(cmd.String(flagState))
			if err != nil {
				return err
			}

			return client(cmd).ForceBoot(device, state)
		},
	}
}

func solCommand() *cli.Command {
	return &cli.Command{
		Name:   "sol",
		Usage:  "attach to the serial-over-LAN console (Ctrl-] to detach)",
		Flags:  connectionFlags(),
		Action: console,
	}
}

func console(ctx context.Context, cmd *cli.Command) error {
	host := cmd.String(flagHost)

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, err := sol.Dial(dialCtx, host, cmd.String(flagUser), cmd.String(flagPass), cmd.Bool(flagTLS))
	if err != nil {
		return err
	}

	if err := conn.Open(); err != nil {
		_ = conn.Close()

		return err
	}

	restore, err := rawMode()
	if err != nil {
		_ = conn.Close()

		return err
	}

	defer restore()

	fmt.Fprintf(os.Stderr, "connected to %s, Ctrl-] to detach\r\n", host)

	return conn.Run(ctx, os.Stdin, cmd.Writer)
}

// rawMode stops local buffering and echo so keystrokes reach the remote console
// as typed. No-op when stdin is not a terminal, so piped input still works.
func rawMode() (func(), error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return func() {}, nil
	}

	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("set raw terminal mode: %w", err)
	}

	return func() {
		_ = term.Restore(fd, state) //nolint:errcheck // the terminal is being torn down anyway
	}, nil
}
