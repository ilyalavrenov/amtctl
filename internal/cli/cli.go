package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	flagHost  = "host"
	flagTLS   = "tls"
	flagUser  = "user"
	flagPass  = "pass"
	flagState = "state"
)

// Run executes the command tree against argv. Cancelling ctx aborts the console
// session; the WSMAN commands cannot observe it, see amt.parameters.
func Run(ctx context.Context, version string, osArgs []string) error {
	cmd := &cli.Command{
		Name:                  "amtctl",
		Usage:                 "out-of-band control for Intel AMT (vPro) machines",
		Version:               version,
		EnableShellCompletion: true,
		Commands: []*cli.Command{
			infoCommand(),
			powerCommand(),
			pxeCommand(),
			solCommand(),
		},
	}

	return cmd.Run(ctx, osArgs) //nolint:wrapcheck // error is already contextual
}

func connectionFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     flagHost,
			Usage:    "AMT host or IP",
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

func infoCommand() *cli.Command {
	return &cli.Command{
		Name:  "info",
		Usage: "report the current power state",
		Flags: connectionFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			state, err := client(cmd).FetchPowerState()
			if err != nil {
				return err
			}

			fmt.Fprintln(cmd.Writer, state)

			return nil
		},
	}
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

func pxeCommand() *cli.Command {
	return &cli.Command{
		Name:  "pxe",
		Usage: "force a one-time PXE boot, then apply the power action",
		Description: "Stages the boot override and enables serial-over-LAN for the next boot, " +
			"so `amtctl sol` shows the PXE boot it triggers.",
		Flags: append(connectionFlags(), stateFlag("reset")),
		Action: func(_ context.Context, cmd *cli.Command) error {
			state, err := amt.ParseState(cmd.String(flagState))
			if err != nil {
				return err
			}

			return client(cmd).ForcePXE(state)
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
