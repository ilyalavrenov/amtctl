# amtctl

Out-of-band control for Intel AMT (vPro) machines: power state, one-time PXE boot
override, a serial-over-LAN console, and the firmware event log. A single static
Go binary.

## Install

```bash
go install github.com/ilyalavrenov/amtctl@latest
```

Or download a binary from the [releases page](https://github.com/ilyalavrenov/amtctl/releases).

## Use

```bash
export AMT_USER=admin AMT_PASS=...

amtctl info    --host amt.example.com                  # power state, AMT version, provisioning
amtctl devices --host amt.example.com                  # boot devices this machine reports
amtctl boot    --host amt.example.com --device pxe     # pxe | hdd | cd, then reset
amtctl power   --host amt.example.com --state reset    # on | off | reset | cycle
amtctl log     --host amt.example.com                  # hardware event log, newest record first
amtctl sol     --host amt.example.com                  # serial console, Ctrl-] to detach
```

Host and credentials come from `AMT_HOST` / `AMT_USER` / `AMT_PASS`, or from
`--host` / `--user` / `--pass`.

`--tls` switches to the TLS ports (16993 WSMAN, 16995 redirection). AMT's default
certificate is self-signed and is **not** verified.

`--json` prints output as JSON.

`boot` enables serial-over-LAN for the boot it stages, so `amtctl sol` shows that
boot. The console stays silent unless the target's kernel logs to one. `devices`
lists what the machine actually offers.

## Notes

Power and boot control are WSMAN calls through Intel's
[go-wsman-messages](https://github.com/device-management-toolkit/go-wsman-messages).
The console speaks the AMT redirection protocol directly, since no Go library
packages it.

## License

MIT, see [LICENSE](LICENSE).
