# Linux Browser VM

Reusable Ubuntu VM for Linux browser testing on this Mac.

## Commands

- `./scripts/linux-vm-up.sh` creates or starts the VM and mounts the full `Parad0x Command` project at `/home/ubuntu/project`.
- `./scripts/linux-vm-provision.sh` installs the Linux desktop, VNC, noVNC, Firefox, and Chromium.
- `./scripts/linux-vm-open.sh` opens the Linux desktop in a browser.
- `./scripts/linux-vm-shell.sh` opens a shell inside the VM.
- `./scripts/linux-vm-exec.sh <command>` runs a command inside `/home/ubuntu/project` in the VM.
- `./scripts/linux-vm-sync-parad0x-command.sh` copies the current Parad0x Command export into the VM at `/home/ubuntu/parad0x-command-test`.
- `./scripts/linux-vm-start-parad0x-command.sh` starts Parad0x Command in the Linux VM.
- `./scripts/linux-vm-stop-parad0x-command.sh` stops Parad0x Command in the Linux VM.
- `./scripts/linux-vm-stop.sh` stops the VM.

## Notes

- The VNC password is stored locally in `.state/linux-browser-lab-vnc-password`.
- The mounted project path inside Linux is `/home/ubuntu/project`.
- Parad0x Command itself is launched from a synced local copy inside the VM at `/home/ubuntu/parad0x-command-test` because the host mount is not reliable for executing the export.
