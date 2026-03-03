# Parad0x Command Center Spec

## Mission
Transform the existing browser-based galaxy map into a real desktop command center for macOS and Linux.

The current galaxy UI already exists and must be preserved as the visual identity.
Do not replace it with a generic dashboard.
Do not rewrite the whole app from scratch unless a subsystem is clearly broken and cannot be reused.

The end result should feel like a sovereign operating layer on top of the OS:
- browser-rendered galaxy/spatial UI
- native bridge for system/app/file control
- local-first architecture
- usable as a daily workspace, not just a pretty animation

## Product Intent
This is not just a wallpaper and not just a passive dashboard.
It is a living command center for human + agent work.

The galaxy remains the home screen and navigation layer.
The UI should surface:
- machine state
- agent state
- task progress
- app/file access
- alerts
- node-to-node activity

The app should feel like mission control while still being practical and fast.

## Target Architecture
Tauri v2 is the preferred desktop wrapper target.

Keep the existing web UI as the frontend.
Add a native backend/bridge for:
- CPU usage
- RAM usage
- GPU information where reasonably accessible
- storage usage
- process/app list
- app launch/focus actions
- file/folder browsing
- recent files/projects
- opening logs, outputs, folders, apps
- local settings/state persistence

Use the existing galaxy visualization as the main shell/home view.
Do not discard the current visual style.

## Required Functional Goals

### 1. Desktop shell
- Wrap the existing web app in Tauri v2.
- App name: `Parad0x Command Center`
- Support macOS and Linux first.
- Add desktop dev mode and packaged production mode.
- Launch into a clean desktop-style window.
- Prefer fullscreen/borderless as an option, not as a hard default.
- Preserve fast startup.

### 2. Native telemetry bridge
Expose backend commands/events so the frontend can query and refresh:
- CPU
- RAM
- storage
- process list
- app state
- uptime/basic system identity

Use efficient polling or event updates.
Avoid wasteful high-frequency refresh.

### 3. Agent control surface
Create a real agent panel, not fake placeholder text.
For each agent, show when available:
- agent name
- current task
- status: idle / running / waiting / error
- percent complete
- ETA or best-effort progress hint
- queue depth
- resource usage
- last update timestamp
- latest error/blocker

If an actual agent backend is not yet available, define a clean adapter interface and wire the UI to structured mock data that can be replaced later.

### 4. Actionable workspace controls
Add real usefulness, not just visuals:
- open folder
- open file
- open recent project
- open logs
- open outputs
- launch app
- reveal active processes/apps in UI
- click node => open related resource or panel

### 5. Galaxy map improvements
Preserve the existing galaxy concept, but make it more useful:
- the map is a spatial relationship layer, not dead decorative space
- nodes should represent real objects where possible:
  - agents
  - apps
  - folders/projects
  - system components
  - alerts
  - flows
- add clearer focus/selection states
- selected node should drive side-panel detail
- reduce meaningless visual clutter if needed
- prioritize readable interaction over pure eye candy

### 6. Modes
Support two modes:
- `Ambient mode`
  - lower motion
  - lower CPU usage
  - useful for always-on display
  - simplified updates
- `Workspace mode`
  - interactive
  - fuller controls
  - richer detail

### 7. Alerts and operational usefulness
Create a visible alert/attention layer for:
- blocked task
- failed task
- high resource pressure
- stalled agent
- missing output
- abnormal conditions

The app should answer quickly:
- what is running?
- what is blocked?
- what needs attention now?
- what can be clicked to act?

## UX Rules
- Keep the visual identity futuristic and premium.
- Do not turn this into a generic admin dashboard.
- Readability matters more than density.
- Important information should be visible at a glance.
- Text sizes must be practical for real use.
- Avoid panel spam.
- Avoid fake metrics unless clearly marked as mock/demo data.
- Preserve the best parts of the current design language.

## Engineering Rules
- Reuse existing code whenever sensible.
- Make minimal, targeted changes first.
- Keep dependencies lean.
- Avoid introducing bloated frameworks unless necessary.
- Prefer small composable modules.
- Separate:
  - UI rendering
  - world/state model
  - native/system bridge
- If current code is messy, refactor only the pieces needed to support the new architecture.
- Do not break the existing visual shell while adding native capabilities.

## Work Phases
Follow this order:
1. Audit the current repo and summarize the existing architecture.
2. Identify the current frontend entrypoint, package manager, and build commands.
3. Create a migration plan before making major changes.
4. Scaffold the Tauri wrapper around the existing app.
5. Connect the frontend to Tauri/native commands.
6. Add the telemetry/system bridge.
7. Add actionable panels and click handlers.
8. Improve galaxy node semantics and selection behavior.
9. Add ambient/workspace modes.
10. Build, run, debug, and fix until the app launches successfully.

## Verification Rules
After each phase:
- explain exactly what changed
- run the relevant build/dev command
- fix compile/runtime errors
- do not stop at partial edits if the project is broken

Before finishing:
- ensure the app starts locally
- ensure the galaxy UI still renders
- ensure at least one native command path works end-to-end
- ensure the app is in a cleaner state than before

## Failure Handling
If dependencies are missing or network access is needed:
- ask for approval and continue
- do not give up early

If the architecture is ambiguous:
- inspect the repo first
- summarize findings
- then proceed

If some features cannot be fully completed in one pass:
- still leave the repo in a runnable state
- implement clean scaffolding/interfaces
- clearly mark TODOs
- prioritize a working desktop shell over unfinished extras

## Definition of Success
Success means:
- the existing galaxy map is now running as a Tauri desktop app
- the app launches locally
- the visual style is preserved
- there is a real native bridge for system data
- there are actionable controls for files/apps/logs/projects
- the UI is more useful than before, not just prettier
